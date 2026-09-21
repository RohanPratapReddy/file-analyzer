// repository-reader (Go): concurrent, strictly READ-ONLY viewer for the SQLite
// database produced by RepositoryDatabaseGenerator (see src/core/db_generator.py).
//
// This program is a WORKER over the analysis VIEWS defined once in Python
// (src/views/catalog.py) and installed into the database by src.views
// (install_views_sqlite / append_views_to_sql_dump, also wired into
// AnalysisEngine.run). It NO LONGER embeds any query SQL of its own: it
// discovers the installed VIEW objects from the database catalog and reads them
// (SELECT * FROM "<view>"). Add/'change a view in Python and every worker picks
// it up with zero code changes here.
//
// GUARANTEES
//   * The source database is opened with mode=ro (SQLITE_OPEN_READONLY).
//   * Every pooled connection has PRAGMA query_only(true) applied.
//   * A start-up canary attempts a write and REQUIRES it to fail; if any write
//     succeeds the program aborts before spawning a single worker.
//   * Workers only ever call db.Query* — never Exec, never a writing txn.
//   * When the source is a .sql text dump, it is loaded ONE TIME into a private
//     temp database (the coordinator's snapshot) BEFORE any worker starts; the
//     views that AnalysisEngine appended to the dump come along in that load.
//
// Concurrency: a fixed pool of goroutines drains a job channel; each job reads
// one installed view. The set can be replayed N times (-repeat) to sustain
// genuinely parallel read load across the pool.
//
// Build:
//   go mod tidy   # fetches modernc.org/sqlite (pure Go, no cgo/gcc needed)
//   go build -o repo-reader .
// Run:
//   ./repo-reader -source ../../../../repository.db
//   ./repo-reader -source ../../../../repository_schema.sql -workers 8 -repeat 3
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const (
	driverName = "sqlite"
	maxRows    = 50 // cap rows printed per view so large views don't flood output
)

// result carries one finished view read back to the coordinator.
type result struct {
	worker   int
	view     string
	rows     int
	elapsed  time.Duration
	body     string
	err      error
	sequence int
}

func main() {
	source := flag.String("source", "repository.db", "path to the .db (opened read-only) or .sql dump (loaded once into a private read-only snapshot)")
	workers := flag.Int("workers", runtime.NumCPU(), "number of concurrent worker goroutines")
	repeat := flag.Int("repeat", 1, "how many times to replay the full view set across the pool")
	verbose := flag.Bool("verbose", false, "print every result body (default prints bodies once per distinct view)")
	// Machine-readable mode: used by the Python launcher (src/views/native_reader.py).
	jsonOut := flag.Bool("json", false, "emit a single JSON object of {view: {columns, rows}} to stdout instead of the human report")
	viewsCSV := flag.String("views", "", "comma-separated subset of installed view names to read (default: all)")
	limit := flag.Int("limit", maxRows, "max rows per view in -json mode (<= 0 means no cap)")
	flag.Parse()

	if *workers < 1 {
		*workers = 1
	}
	if *repeat < 1 {
		*repeat = 1
	}

	dbPath, cleanup, err := resolveSource(*source)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
	defer cleanup()

	db, err := openReadOnly(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: opening read-only db: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()
	// Bound the pool to the worker count so we exercise real concurrency.
	db.SetMaxOpenConns(*workers)
	db.SetMaxIdleConns(*workers)

	if err := verifyReadOnly(db); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: read-only guarantee failed: %v\n", err)
		os.Exit(1)
	}

	viewNames, err := installedViews(db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: reading view catalog: %v\n", err)
		os.Exit(1)
	}

	// Machine-readable path: read the (optionally filtered) views concurrently and
	// emit ONE JSON object to stdout. All diagnostics go to stderr so stdout stays
	// pure JSON for the Python launcher to parse.
	if *jsonOut {
		emitJSON(db, viewNames, *viewsCSV, *workers, *limit)
		return
	}

	fmt.Printf("== repository-reader (Go) ==\n")
	fmt.Printf("source     : %s\n", *source)
	fmt.Printf("read-only  : verified (write canary rejected)\n")
	fmt.Printf("workers    : %d   repeat: %d   views: %d\n\n", *workers, *repeat, len(viewNames))

	if len(viewNames) == 0 {
		fmt.Println("no analysis views found in the database.")
		fmt.Println("install them first, e.g.:  python -m src.views install", *source)
		fmt.Println("(AnalysisEngine.run installs them automatically for its outputs.)")
		return
	}

	// Build the job list: each (view, iteration) pair is one job.
	type job struct {
		view string
		seq  int
	}
	var jobs []job
	seq := 0
	for r := 0; r < *repeat; r++ {
		for _, v := range viewNames {
			jobs = append(jobs, job{view: v, seq: seq})
			seq++
		}
	}

	jobCh := make(chan job)
	resCh := make(chan result, len(jobs))
	var executed int64

	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			ctx := context.Background()
			for j := range jobCh {
				start := time.Now()
				body, n, err := runView(ctx, db, j.view)
				atomic.AddInt64(&executed, 1)
				resCh <- result{
					worker:   workerID,
					view:     j.view,
					rows:     n,
					elapsed:  time.Since(start),
					body:     body,
					err:      err,
					sequence: j.seq,
				}
			}
		}(w)
	}

	wallStart := time.Now()
	go func() {
		for _, j := range jobs {
			jobCh <- j
		}
		close(jobCh)
	}()

	go func() {
		wg.Wait()
		close(resCh)
	}()

	var results []result
	for r := range resCh {
		results = append(results, r)
	}
	wall := time.Since(wallStart)

	// Deterministic ordering for the report (jobs finished out of order).
	sort.Slice(results, func(i, j int) bool { return results[i].sequence < results[j].sequence })

	printedBody := map[string]bool{}
	var failures int
	for _, r := range results {
		if r.err != nil {
			failures++
			fmt.Printf("[w%02d] %-34s ERROR: %v\n", r.worker, r.view, r.err)
			continue
		}
		fmt.Printf("[w%02d] %-34s %3d rows  %8s\n", r.worker, r.view, r.rows, r.elapsed.Round(time.Microsecond))
		if *verbose || !printedBody[r.view] {
			printedBody[r.view] = true
			fmt.Print(indent(r.body))
		}
	}

	fmt.Printf("\n-- summary --\n")
	fmt.Printf("queries executed : %d\n", atomic.LoadInt64(&executed))
	fmt.Printf("failures         : %d\n", failures)
	fmt.Printf("wall clock       : %s (concurrent across %d workers)\n", wall.Round(time.Millisecond), *workers)
	if failures > 0 {
		os.Exit(2)
	}
}

// resolveSource returns a path to a SQLite database. A .db/.sqlite is used in
// place; a .sql dump is materialized once into a private temp database that the
// workers then read read-only. The returned cleanup removes any temp file.
func resolveSource(source string) (dbPath string, cleanup func(), err error) {
	noop := func() {}
	info, statErr := os.Stat(source)
	if statErr != nil {
		return "", noop, fmt.Errorf("source not found: %s", source)
	}
	if info.IsDir() {
		return "", noop, fmt.Errorf("source is a directory: %s", source)
	}

	ext := strings.ToLower(filepath.Ext(source))
	if ext == ".sql" {
		return loadSQLDump(source)
	}
	// Treat everything else (.db/.sqlite/.sqlite3/...) as a SQLite database.
	return source, noop, nil
}

// loadSQLDump builds a one-time private snapshot from a .sql dump. This is the
// ONLY write the program performs, it targets a fresh temp file (never the
// source), and it completes before any worker starts. Any CREATE VIEW that
// AnalysisEngine appended to the dump is created here as part of the load.
func loadSQLDump(sqlPath string) (string, func(), error) {
	script, err := os.ReadFile(sqlPath)
	if err != nil {
		return "", func() {}, fmt.Errorf("reading dump: %w", err)
	}
	tmp, err := os.CreateTemp("", "repo-snapshot-*.db")
	if err != nil {
		return "", func() {}, fmt.Errorf("creating temp snapshot: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	cleanup := func() { os.Remove(tmpPath) }

	// Writable handle used only for the load; discarded immediately after.
	loader, err := sql.Open(driverName, "file:"+tmpPath+"?_pragma=foreign_keys(off)")
	if err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("opening loader: %w", err)
	}
	// modernc.org/sqlite executes every statement in a multi-statement string,
	// letting SQLite's own parser handle comments and quoting correctly.
	if _, err := loader.Exec(string(script)); err != nil {
		loader.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("loading dump into snapshot: %w", err)
	}
	loader.Close()
	// stderr, not stdout: -json mode requires stdout to carry only the JSON object.
	fmt.Fprintf(os.Stderr, "(loaded .sql dump into private read-only snapshot: %s)\n", tmpPath)
	return tmpPath, cleanup, nil
}

// openReadOnly opens the database with mode=ro and query_only enforced, plus a
// busy timeout so concurrent readers never trip over a transient lock.
func openReadOnly(dbPath string) (*sql.DB, error) {
	dsn := "file:" + dbPath + "?mode=ro&_pragma=query_only(true)&_pragma=busy_timeout(5000)"
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

// verifyReadOnly proves the handle cannot mutate: a write MUST be rejected.
func verifyReadOnly(db *sql.DB) error {
	_, err := db.Exec("CREATE TABLE __readonly_canary__ (x INTEGER)")
	if err == nil {
		return errors.New("write canary SUCCEEDED — database is NOT read-only, aborting")
	}
	return nil
}

// installedViews returns the names of the analysis VIEW objects present in the
// database (built from src/views/catalog.py). This replaces the previously
// hard-coded query catalog: the workers read whatever views are installed.
func installedViews(db *sql.DB) ([]string, error) {
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type = 'view' ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// runView reads one installed view and renders the rows generically. The view
// name comes from the database's own catalog, so the identifier is trusted; it
// is still double-quoted for correctness.
func runView(ctx context.Context, db *sql.DB, viewName string) (string, int, error) {
	query := `SELECT * FROM "` + strings.ReplaceAll(viewName, `"`, `""`) + `"`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return "", 0, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return "", 0, err
	}
	var sb strings.Builder
	sb.WriteString(strings.Join(cols, " | "))
	sb.WriteString("\n")

	count := 0
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return "", count, err
		}
		if count < maxRows {
			cells := make([]string, len(cols))
			for i := range vals {
				cells[i] = cell(vals[i])
			}
			sb.WriteString(strings.Join(cells, " | "))
			sb.WriteString("\n")
		} else if count == maxRows {
			sb.WriteString("... (row output truncated)\n")
		}
		count++
	}
	return sb.String(), count, rows.Err()
}

// viewJSON is one view's payload in the machine-readable output.
type viewJSON struct {
	Columns []string `json:"columns"`
	Rows    [][]any  `json:"rows"`
}

// emitJSON reads the requested views concurrently and writes a single JSON object
// {"engine","views":{name:{columns,rows}},"errors":{name:msg}} to stdout. Values
// are decoded generically; []byte cells become strings so the JSON is readable.
func emitJSON(db *sql.DB, viewNames []string, viewsCSV string, workers, limit int) {
	wanted := parseCSVSet(viewsCSV) // empty set => all views
	views := map[string]viewJSON{}
	errs := map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	ctx := context.Background()
	for _, v := range viewNames {
		if len(wanted) > 0 && !wanted[v] {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(view string) {
			defer wg.Done()
			defer func() { <-sem }()
			cols, rows, err := readViewStructured(ctx, db, view, limit)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs[view] = err.Error()
				return
			}
			if rows == nil {
				rows = [][]any{}
			}
			views[view] = viewJSON{Columns: cols, Rows: rows}
		}(v)
	}
	wg.Wait()
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(map[string]any{"engine": "go", "views": views, "errors": errs}); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: encoding json: %v\n", err)
		os.Exit(1)
	}
}

// readViewStructured reads one view into (columns, rows) with []byte cells coerced
// to strings so they encode as JSON text rather than base64.
func readViewStructured(ctx context.Context, db *sql.DB, viewName string, limit int) ([]string, [][]any, error) {
	query := `SELECT * FROM "` + strings.ReplaceAll(viewName, `"`, `""`) + `"`
	if limit > 0 {
		query += " LIMIT " + strconv.Itoa(limit)
	}
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, nil, err
	}
	var out [][]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return cols, out, err
		}
		rec := make([]any, len(cols))
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				rec[i] = string(b)
			} else {
				rec[i] = v
			}
		}
		out = append(out, rec)
	}
	return cols, out, rows.Err()
}

// parseCSVSet turns "a,b, c" into {"a","b","c"}; an empty string yields an empty
// set (meaning "no filter" to the caller).
func parseCSVSet(csv string) map[string]bool {
	set := map[string]bool{}
	for _, part := range strings.Split(csv, ",") {
		if p := strings.TrimSpace(part); p != "" {
			set[p] = true
		}
	}
	return set
}

func cell(v any) string {
	switch t := v.(type) {
	case nil:
		return "NULL"
	case []byte:
		return string(t)
	default:
		return fmt.Sprintf("%v", t)
	}
}

func indent(body string) string {
	var sb strings.Builder
	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		sb.WriteString("        ")
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	return sb.String()
}
