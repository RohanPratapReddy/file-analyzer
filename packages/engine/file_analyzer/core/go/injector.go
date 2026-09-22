// repository-injector (Go): concurrent bulk loader for the SQLite database
// produced by RepositoryDatabaseGenerator (see file_analyzer/core/db_generator.py).
//
// ROLE
//   RepositoryDatabaseGenerator.export_to_sqlite_db_concurrent builds the table
//   STRUCTURE once (DROP/CREATE/triggers) on a single connection, then needs the
//   generated INSERT section injected into the file. The Python side partitions
//   that section into independent per-table blocks (one contiguous run of INSERTs
//   under a single `-- Ingesting "<table>"` marker) and stages each block as
//   <blocks-dir>/block_<id>.sql, with a manifest.json listing {id,label,file}.
//   This program injects those blocks CONCURRENTLY: a fixed pool of goroutines
//   drains a job channel and applies one block per job, each on its own pooled
//   connection. Because every block targets a DISTINCT table, concurrent writers
//   never conflict on rows; SQLite (WAL + busy_timeout) serializes the physical
//   page writes safely.
//
//   This is the "writes" counterpart of file_analyzer/views/go/main.go (the
//   read-only view reader): same modernc.org/sqlite pure-Go driver (no cgo/gcc),
//   same goroutine-pool shape. It is a concurrency driver over SQL the Python
//   generator emitted; it never builds SQL of its own and never reimplements the
//   generator.
//
// GUARANTEES / SAFETY
//   * The structure is already present when this runs -- the program only INSERTs.
//   * foreign_keys are OFF during the load (as in the .sql dump path); the caller
//     re-enables + optimizes afterwards.
//   * Every block is applied inside its own transaction, so a failing block rolls
//     back cleanly and is reported without corrupting the others.
//   * Any block failure makes the program exit non-zero AFTER attempting them all,
//     and the failing labels are reported (stderr + the JSON summary) so the
//     Python driver can fall back to its in-process injector.
//
// Build:
//   go build -o repo-injector .
// Run:
//   ./repo-injector -db repository.db -blocks-dir <dir> -workers 8 [-json]
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const driverName = "sqlite"

// blockSpec is one entry of the staged manifest.json the Python driver writes.
type blockSpec struct {
	ID    int    `json:"id"`
	Label string `json:"label"`
	File  string `json:"file"`
}

// manifest is the whole staged job: which blocks to inject, in order.
type manifest struct {
	Blocks []blockSpec `json:"blocks"`
}

// result carries one finished block injection back to the coordinator.
type result struct {
	id      int
	label   string
	err     error
	elapsed time.Duration
}

func main() {
	dbPath := flag.String("db", "repository.db", "path to the SQLite database (structure already created)")
	blocksDir := flag.String("blocks-dir", "", "directory holding manifest.json + block_<id>.sql files")
	workers := flag.Int("workers", runtime.NumCPU(), "number of concurrent injector goroutines")
	jsonOut := flag.Bool("json", false, "emit a JSON summary to stdout instead of the human report")
	flag.Parse()

	if *blocksDir == "" {
		fmt.Fprintln(os.Stderr, "fatal: -blocks-dir is required")
		os.Exit(2)
	}
	if *workers < 1 {
		*workers = 1
	}

	man, err := loadManifest(*blocksDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: reading manifest: %v\n", err)
		os.Exit(1)
	}
	if len(man.Blocks) == 0 {
		if *jsonOut {
			emit(map[string]any{"engine": "go", "injected": 0, "failures": map[string]string{}})
		} else {
			fmt.Println("== repository-injector (Go) == no blocks to inject")
		}
		return
	}

	db, err := openWritable(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: opening db: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()
	// One physical connection per worker so blocks truly overlap.
	db.SetMaxOpenConns(*workers)
	db.SetMaxIdleConns(*workers)

	jobCh := make(chan blockSpec)
	resCh := make(chan result, len(man.Blocks))
	var executed int64

	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			for b := range jobCh {
				start := time.Now()
				e := injectBlock(ctx, db, filepath.Join(*blocksDir, b.File))
				atomic.AddInt64(&executed, 1)
				resCh <- result{id: b.ID, label: b.Label, err: e, elapsed: time.Since(start)}
			}
		}()
	}

	go func() {
		for _, b := range man.Blocks {
			jobCh <- b
		}
		close(jobCh)
	}()
	go func() {
		wg.Wait()
		close(resCh)
	}()

	failures := map[string]string{}
	injected := 0
	for r := range resCh {
		if r.err != nil {
			failures[r.label] = r.err.Error()
			if !*jsonOut {
				fmt.Printf("[inject] %-40s ERROR: %v\n", r.label, r.err)
			}
			continue
		}
		injected++
		if !*jsonOut {
			fmt.Printf("[inject] %-40s OK  (%s)\n", r.label, r.elapsed.Round(time.Millisecond))
		}
	}

	if *jsonOut {
		emit(map[string]any{"engine": "go", "injected": injected, "failures": failures})
	} else {
		fmt.Printf("\n-- summary --\nblocks: %d  injected: %d  failures: %d\n",
			len(man.Blocks), injected, len(failures))
	}
	if len(failures) > 0 {
		os.Exit(1)
	}
}

func loadManifest(dir string) (manifest, error) {
	var man manifest
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return man, err
	}
	if err := json.Unmarshal(raw, &man); err != nil {
		return man, err
	}
	return man, nil
}

// openWritable opens the db for the bulk load with the same pragmas the Python
// concurrent injector uses: WAL journalling, no per-statement fsync, a generous
// busy timeout so pooled writers wait rather than fail, and foreign keys off.
func openWritable(dbPath string) (*sql.DB, error) {
	dsn := "file:" + dbPath +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(off)" +
		"&_pragma=busy_timeout(60000)" +
		"&_pragma=foreign_keys(off)"
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// injectBlock applies one staged block file inside its own transaction. The
// block is a run of INSERTs against a single table (SQL the Python generator
// emitted); modernc's driver executes the multi-statement string via SQLite's
// own parser, so embedded newlines in value literals are handled correctly.
func injectBlock(ctx context.Context, db *sql.DB, path string) error {
	script, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, string(script)); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func emit(payload map[string]any) {
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(payload); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: encoding json: %v\n", err)
		os.Exit(1)
	}
}
