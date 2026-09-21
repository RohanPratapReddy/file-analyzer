// tabgen analysis plane (Go): a concurrent worker pool that drives per-shard
// analysis by fanning out to the Python per-shard worker (src/router/worker.py).
//
// ROLE
//   This is one of the two "planes" (Go + Java) the router uses to run the
//   repository's analyzers in parallel. The routing decision (which file goes to
//   which analyzer class) is made in Python and staged in <temp>/mapping.json;
//   this plane is handed a subset of the resulting shard ids and is responsible
//   for executing them concurrently. Each shard becomes one child process:
//
//       python worker.py --readers-root <root> --temp <temp> --shard <id>
//
//   A fixed pool of goroutines drains a shard channel, so N shards run across
//   up to -workers concurrent OS processes. The plane never touches the database
//   and never reimplements analysis — it is a concurrency driver only.
//
// Build:
//   go build -o analysis-plane .
// Run:
//   ./analysis-plane -python python -readers-root ../../.. -temp <temp> \
//                    -shards shard_code,shard_data -workers 4
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type shardResult struct {
	shard   string
	err     error
	elapsed time.Duration
}

func main() {
	python := flag.String("python", "python", "python interpreter used to run the per-shard worker")
	readersRoot := flag.String("readers-root", "", "path to the 'readers' directory (so 'from src import ...' resolves)")
	temp := flag.String("temp", "", "temp/ staging directory")
	shardsCSV := flag.String("shards", "", "comma-separated shard ids this plane must analyze")
	workers := flag.Int("workers", runtime.NumCPU(), "max concurrent worker processes")
	flag.Parse()

	if *readersRoot == "" || *temp == "" {
		fmt.Fprintln(os.Stderr, "fatal: -readers-root and -temp are required")
		os.Exit(2)
	}
	shards := splitNonEmpty(*shardsCSV)
	if len(shards) == 0 {
		fmt.Println("== analysis-plane (Go) == no shards assigned; nothing to do")
		return
	}
	if *workers < 1 {
		*workers = 1
	}

	workerScript := filepath.Join(*readersRoot, "src", "router", "worker.py")

	fmt.Printf("== analysis-plane (Go) ==\n")
	fmt.Printf("shards   : %s\n", strings.Join(shards, ", "))
	fmt.Printf("workers  : %d (concurrent processes)\n\n", *workers)

	shardCh := make(chan string)
	resCh := make(chan shardResult, len(shards))

	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range shardCh {
				start := time.Now()
				err := runWorker(*python, workerScript, *readersRoot, *temp, s)
				resCh <- shardResult{shard: s, err: err, elapsed: time.Since(start)}
			}
		}()
	}

	go func() {
		for _, s := range shards {
			shardCh <- s
		}
		close(shardCh)
	}()

	go func() {
		wg.Wait()
		close(resCh)
	}()

	var failures int
	for r := range resCh {
		if r.err != nil {
			failures++
			fmt.Printf("[go] %-16s ERROR (%s): %v\n", r.shard, r.elapsed.Round(time.Millisecond), r.err)
		} else {
			fmt.Printf("[go] %-16s OK    (%s)\n", r.shard, r.elapsed.Round(time.Millisecond))
		}
	}

	fmt.Printf("\n-- plane summary --\nshards: %d  failures: %d\n", len(shards), failures)
	if failures > 0 {
		os.Exit(1)
	}
}

// runWorker executes one per-shard Python worker as a child process, streaming
// its stdout/stderr through so the parent orchestrator sees a unified log.
func runWorker(python, script, readersRoot, temp, shard string) error {
	cmd := exec.Command(python, script,
		"--readers-root", readersRoot,
		"--temp", temp,
		"--shard", shard,
	)
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
