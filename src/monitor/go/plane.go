// monitor worker pool (Go): a concurrent goroutine pool that drives incremental
// per-file re-analysis by fanning out to the Python batch worker
// (src/monitor/worker.py, i.e. `python -m src.monitor.worker`).
//
// ROLE
//   The repository monitor detects which files changed (created/modified) in a
//   scan cycle and needs them re-analyzed quickly. The Python side partitions the
//   changed files into batches and stages one <out>/batches/batch_<id>.json per
//   batch; this pool is handed the batch ids and runs them concurrently, one
//   child process per batch:
//
//       python -m src.monitor.worker --readers-root <root> --out <out> --batch <f>
//
//   A fixed pool of goroutines (sized between -min-workers and -max-workers, and
//   never more than the number of batches) drains a batch channel, so many
//   batches run across concurrent OS processes at once. The pool never touches
//   the diff database and never reimplements analysis -- it is a concurrency
//   driver only; the Python worker does the work and the Python monitor ingests
//   the results.
//
// Zombie-safety: each child is fully waited on (cmd.Wait) after its stdout/stderr
// pipes drain, so no defunct child processes are left behind.
//
// Build:
//   go build -o monitor-pool .
// Run:
//   ./monitor-pool -python python -readers-root ../../.. -out <out> \
//                  -batch-ids 0,1,2 -min-workers 16 -max-workers 128
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type batchResult struct {
	id      string
	err     error
	elapsed time.Duration
}

func main() {
	python := flag.String("python", "python", "python interpreter used to run the batch worker")
	readersRoot := flag.String("readers-root", "", "path to the 'readers' directory (so 'import src' resolves)")
	out := flag.String("out", "", "pool output directory (holds batches/ and results/)")
	batchIDsCSV := flag.String("batch-ids", "", "comma-separated batch ids to run")
	minWorkers := flag.Int("min-workers", 16, "worker-pool floor (when there is that much work)")
	maxWorkers := flag.Int("max-workers", 128, "worker-pool ceiling")
	flag.Parse()

	if *readersRoot == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "fatal: -readers-root and -out are required")
		os.Exit(2)
	}
	ids := splitNonEmpty(*batchIDsCSV)
	if len(ids) == 0 {
		fmt.Println("== monitor-pool (Go) == no batches assigned; nothing to do")
		return
	}

	workers := effectiveWorkers(len(ids), *minWorkers, *maxWorkers)
	workerScript := filepath.Join(*readersRoot, "src", "monitor", "worker.py")

	fmt.Printf("== monitor-pool (Go) ==\n")
	fmt.Printf("batches  : %d\n", len(ids))
	fmt.Printf("workers  : %d (concurrent processes; floor %d / ceiling %d)\n\n",
		workers, *minWorkers, *maxWorkers)

	batchCh := make(chan string)
	resCh := make(chan batchResult, len(ids))

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range batchCh {
				start := time.Now()
				err := runWorker(*python, *readersRoot, workerScript, *out, id)
				resCh <- batchResult{id: id, err: err, elapsed: time.Since(start)}
			}
		}()
	}

	go func() {
		for _, id := range ids {
			batchCh <- id
		}
		close(batchCh)
	}()

	go func() {
		wg.Wait()
		close(resCh)
	}()

	var failures int
	for r := range resCh {
		if r.err != nil {
			failures++
			fmt.Printf("[go] batch %-4s ERROR (%s): %v\n", r.id, r.elapsed.Round(time.Millisecond), r.err)
		} else {
			fmt.Printf("[go] batch %-4s OK    (%s)\n", r.id, r.elapsed.Round(time.Millisecond))
		}
	}

	fmt.Printf("\n-- pool summary --\nbatches: %d  failures: %d\n", len(ids), failures)
	if failures > 0 {
		os.Exit(1)
	}
}

// effectiveWorkers clamps the pool size to [min, max] and never exceeds the
// number of batches (no point spawning idle goroutines).
func effectiveWorkers(nBatches, minW, maxW int) int {
	if maxW < 1 {
		maxW = 1
	}
	if minW < 1 {
		minW = 1
	}
	w := nBatches
	if w > maxW {
		w = maxW
	}
	if w < minW && nBatches >= minW {
		w = minW
	}
	if w > nBatches {
		w = nBatches
	}
	if w < 1 {
		w = 1
	}
	return w
}

// runWorker executes one batch worker as a child process. Its working directory
// is the readers root so `python -m src.monitor.worker` resolves the package.
func runWorker(python, readersRoot, script, out, id string) error {
	batchFile := filepath.Join(out, "batches", "batch_"+id+".json")
	cmd := exec.Command(python, "-m", "src.monitor.worker",
		"--readers-root", readersRoot,
		"--out", out,
		"--batch", batchFile,
	)
	cmd.Dir = readersRoot
	_ = script // path retained for clarity/logging; -m form is used to launch
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	var pipeWg sync.WaitGroup
	pipeWg.Add(2)
	go streamPrefixed(&pipeWg, stdout, "    ")
	go streamPrefixed(&pipeWg, stderr, "    ! ")
	pipeWg.Wait()
	return cmd.Wait()
}

func streamPrefixed(wg *sync.WaitGroup, r interface{ Read([]byte) (int, error) }, prefix string) {
	defer wg.Done()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		fmt.Printf("%s%s\n", prefix, sc.Text())
	}
}

func splitNonEmpty(csv string) []string {
	var out []string
	for _, p := range strings.Split(csv, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
