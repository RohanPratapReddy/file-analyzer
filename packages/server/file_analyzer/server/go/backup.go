// server backup pool (Go): a concurrent goroutine pool that drives per-database
// backups by fanning out to the Python batch worker
// (file_analyzer/server/backup_worker.py, i.e. `python -m file_analyzer.server.backup_worker`).
//
// ROLE
//   The server backs up every database it hosts on a schedule. The Python side
//   (file_analyzer/server/backup_pool.py) partitions the storage keys into
//   batches, stages one job spec.json plus one <out>/batches/batch_<id>.json per
//   batch, and hands this pool the batch ids. A fixed pool of goroutines drains
//   a batch channel and runs each batch concurrently, one child process per batch:
//
//       python -m file_analyzer.server.backup_worker \
//           --spec <spec> --out <out> --batch <batch_<id>.json> \
//           [--readers-root <r> ...]
//
//   Distinct storage keys own disjoint on-disk backup subtrees and per-key locks,
//   so batches back up in parallel with no contention. The pool never touches a
//   database or a backup file and never reimplements the snapshot/chunk/rotation
//   logic -- it is a concurrency driver only; the Python worker does the work and
//   its manifests are what the caller collects, so every backup restores
//   identically regardless of which process produced it.
//
// Zombie-safety: each child is fully waited on (cmd.Wait) after its stdout/stderr
// pipes drain, so no defunct child processes are left behind.
//
// Build:
//   go build -o backup-pool .
// Run:
//   ./backup-pool -python python -spec <spec> -out <out> \
//                 -batch-ids 0,1,2 -readers-roots <r1><sep><r2> \
//                 -min-workers 4 -max-workers 32
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
	python := flag.String("python", "python", "python interpreter used to run the backup worker")
	spec := flag.String("spec", "", "path to the job-spec JSON file")
	out := flag.String("out", "", "pool output directory (holds batches/ and results/)")
	batchIDsCSV := flag.String("batch-ids", "", "comma-separated batch ids to run")
	readersRootsCSV := flag.String("readers-roots", "", "os.pathsep-joined sys.path roots for 'file_analyzer.server' (may be empty)")
	minWorkers := flag.Int("min-workers", 4, "worker-pool floor (when there is that much work)")
	maxWorkers := flag.Int("max-workers", 32, "worker-pool ceiling")
	flag.Parse()

	if *spec == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "fatal: -spec and -out are required")
		os.Exit(2)
	}
	ids := splitNonEmpty(*batchIDsCSV, ",")
	if len(ids) == 0 {
		fmt.Println("== backup-pool (Go) == no batches assigned; nothing to do")
		return
	}
	roots := splitNonEmpty(*readersRootsCSV, string(os.PathListSeparator))

	workers := effectiveWorkers(len(ids), *minWorkers, *maxWorkers)

	fmt.Printf("== backup-pool (Go) ==\n")
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
				err := runWorker(*python, *spec, *out, id, roots)
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

// runWorker executes one batch worker as a child process. When readers roots are
// supplied (an un-installed/editable checkout where the file_analyzer namespace is
// split across packages/*), they are put on the child's PYTHONPATH so that
// `python -m file_analyzer.server.backup_worker` resolves the module at launch --
// the `--readers-root` args alone cannot, because -m resolution happens before the
// worker runs. Both are passed (env for -m; args as a belt-and-suspenders sys.path
// insert). When the package is installed, roots is empty and neither is needed.
func runWorker(python, spec, out, id string, roots []string) error {
	batchFile := filepath.Join(out, "batches", "batch_"+id+".json")
	args := []string{
		"-m", "file_analyzer.server.backup_worker",
		"--spec", spec,
		"--out", out,
		"--batch", batchFile,
	}
	for _, r := range roots {
		args = append(args, "--readers-root", r)
	}
	cmd := exec.Command(python, args...)
	if len(roots) > 0 {
		cmd.Dir = roots[0]
		cmd.Env = envWithPythonPath(os.Environ(), roots)
	}
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

// envWithPythonPath returns a copy of env with the given roots prepended to the
// PYTHONPATH entry (creating it if absent), so a child `python -m ...` can resolve
// modules from an editable, split-namespace checkout.
func envWithPythonPath(env, roots []string) []string {
	sep := string(os.PathListSeparator)
	prefix := strings.Join(roots, sep)
	out := make([]string, 0, len(env)+1)
	found := false
	for _, kv := range env {
		if strings.HasPrefix(kv, "PYTHONPATH=") {
			existing := kv[len("PYTHONPATH="):]
			if existing != "" {
				out = append(out, "PYTHONPATH="+prefix+sep+existing)
			} else {
				out = append(out, "PYTHONPATH="+prefix)
			}
			found = true
		} else {
			out = append(out, kv)
		}
	}
	if !found {
		out = append(out, "PYTHONPATH="+prefix)
	}
	return out
}

func streamPrefixed(wg *sync.WaitGroup, r interface{ Read([]byte) (int, error) }, prefix string) {
	defer wg.Done()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		fmt.Printf("%s%s\n", prefix, sc.Text())
	}
}

func splitNonEmpty(s, sep string) []string {
	var out []string
	for _, p := range strings.Split(s, sep) {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
