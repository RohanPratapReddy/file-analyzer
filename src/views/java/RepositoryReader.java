// RepositoryReader (Java): concurrent, strictly READ-ONLY viewer for the SQLite
// database produced by RepositoryDatabaseGenerator (see src/core/db_generator.py).
//
// This program is a WORKER over the analysis VIEWS defined once in Python
// (src/views/catalog.py) and installed into the database by src.views
// (install_views_sqlite / append_views_to_sql_dump, also wired into
// AnalysisEngine.run). It NO LONGER embeds any query SQL of its own: it
// discovers the installed VIEW objects from the database catalog and reads them
// (SELECT * FROM "<view>"). Add/change a view in Python and every worker picks
// it up with zero code changes here.
//
// GUARANTEES
//   * Each worker opens its OWN connection with open_mode=SQLITE_OPEN_READONLY
//     and PRAGMA query_only = true.
//   * A start-up canary attempts a write and REQUIRES it to fail; if any write
//     succeeds the program aborts before spawning a single worker.
//   * Workers only ever run SELECT via Statement.executeQuery — never
//     executeUpdate, never a commit, never DDL/DML. Zero writes / zero commits.
//   * When the source is a .sql text dump it is loaded ONE TIME into a private
//     temp database (the coordinator's snapshot) using a quote/comment-aware
//     splitter; that temp copy is what the read-only workers see. The original
//     .sql file is never modified, and the load (including the CREATE VIEW
//     statements AnalysisEngine appended) finishes before any worker runs.
//
// Concurrency: a fixed ExecutorService of worker threads; each submitted task is
// one installed view that opens its own read-only connection, queries, closes.
// The view set can be replayed N times (-repeat) to sustain parallel load.
//
// Build (needs the SQLite JDBC driver, e.g. sqlite-jdbc-3.45.x.jar):
//   javac -cp sqlite-jdbc.jar RepositoryReader.java
// Run:
//   java  -cp ".;sqlite-jdbc.jar" RepositoryReader -source ..\..\..\..\repository.db          (Windows)
//   java  -cp ".:sqlite-jdbc.jar" RepositoryReader -source ../../../../repository_schema.sql -workers 8 -repeat 3  (Unix)

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

public class RepositoryReader {

    static final int MAX_ROWS = 50; // cap rows printed per view

    /** Result of one view execution. */
    record Result(int worker, int sequence, String view, int rows,
                  long micros, String body, String error) {}

    public static void main(String[] args) throws Exception {
        String source = "repository.db";
        int workers = Runtime.getRuntime().availableProcessors();
        int repeat = 1;
        boolean verbose = false;
        // Machine-readable mode: used by the Python launcher (src/views/native_reader.py).
        boolean jsonOut = false;
        String viewsCsv = "";
        int limit = MAX_ROWS;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-source" -> source = args[++i];
                case "-workers" -> workers = Math.max(1, Integer.parseInt(args[++i]));
                case "-repeat" -> repeat = Math.max(1, Integer.parseInt(args[++i]));
                case "-verbose" -> verbose = true;
                case "-json" -> jsonOut = true;
                case "-views" -> viewsCsv = args[++i];
                case "-limit" -> limit = Integer.parseInt(args[++i]);
                default -> { System.err.println("unknown arg: " + args[i]); System.exit(1); }
            }
        }

        // Ensure the JDBC driver is present with a clear message if it is not.
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            System.err.println("fatal: org.sqlite.JDBC not on classpath. Add sqlite-jdbc-<ver>.jar (see README).");
            System.exit(1);
        }

        Path[] holder;
        try {
            holder = resolveSource(source);
        } catch (Exception e) {
            System.err.println("fatal: " + e.getMessage());
            System.exit(1);
            return;
        }
        Path dbPath = holder[0];
        Path tempToDelete = holder[1]; // null unless we built a snapshot

        try {
            verifyReadOnly(dbPath);
            List<String> viewNames = installedViews(dbPath);

            // Machine-readable path: read the (optionally filtered) views concurrently
            // and emit ONE JSON object to stdout. Diagnostics stay on stderr so stdout
            // is pure JSON for the Python launcher. The finally block still cleans temp.
            if (jsonOut) {
                emitJson(dbPath, viewNames, viewsCsv, workers, limit);
                return;
            }

            System.out.println("== RepositoryReader (Java) ==");
            System.out.println("source     : " + source);
            System.out.println("read-only  : verified (write canary rejected)");
            System.out.printf("workers    : %d   repeat: %d   views: %d%n%n", workers, repeat, viewNames.size());

            if (viewNames.isEmpty()) {
                System.out.println("no analysis views found in the database.");
                System.out.println("install them first, e.g.:  python -m src.views install " + source);
                System.out.println("(AnalysisEngine.run installs them automatically for its outputs.)");
                return;
            }

            // Build the job list: each (viewName, iteration) pair is one job.
            final Path db = dbPath;
            List<String[]> jobs = new ArrayList<>(); // {viewName, sequenceAsString}
            int seq = 0;
            for (int r = 0; r < repeat; r++) {
                for (String name : viewNames) {
                    jobs.add(new String[]{name, Integer.toString(seq++)});
                }
            }

            AtomicInteger executed = new AtomicInteger();
            ExecutorService pool = Executors.newFixedThreadPool(workers);
            List<Future<Result>> futures = new ArrayList<>();
            long wallStart = System.nanoTime();

            for (String[] job : jobs) {
                final String viewName = job[0];
                final int sequence = Integer.parseInt(job[1]);
                futures.add(pool.submit((Callable<Result>) () -> {
                    int worker = (int) (Thread.currentThread().threadId() % 1000);
                    long start = System.nanoTime();
                    try {
                        String[] out = runView(db, viewName);
                        long micros = (System.nanoTime() - start) / 1000;
                        executed.incrementAndGet();
                        return new Result(worker, sequence, viewName,
                            Integer.parseInt(out[1]), micros, out[0], null);
                    } catch (Exception ex) {
                        executed.incrementAndGet();
                        return new Result(worker, sequence, viewName, 0,
                            (System.nanoTime() - start) / 1000, "", ex.getMessage());
                    }
                }));
            }

            pool.shutdown();

            List<Result> results = new ArrayList<>();
            for (Future<Result> f : futures) {
                results.add(f.get());
            }
            long wallMs = (System.nanoTime() - wallStart) / 1_000_000;

            results.sort((a, b) -> Integer.compare(a.sequence(), b.sequence()));

            Set<String> printedBody = new HashSet<>();
            int failures = 0;
            for (Result r : results) {
                if (r.error() != null) {
                    failures++;
                    System.out.printf("[t%03d] %-34s ERROR: %s%n", r.worker(), r.view(), r.error());
                    continue;
                }
                System.out.printf("[t%03d] %-34s %3d rows  %8d us%n", r.worker(), r.view(), r.rows(), r.micros());
                if (verbose || printedBody.add(r.view())) {
                    System.out.print(indent(r.body()));
                }
            }

            System.out.println();
            System.out.println("-- summary --");
            System.out.println("queries executed : " + executed.get());
            System.out.println("failures         : " + failures);
            System.out.printf("wall clock       : %d ms (concurrent across %d workers)%n", wallMs, workers);
            if (failures > 0) {
                System.exit(2);
            }
        } finally {
            if (tempToDelete != null) {
                try { Files.deleteIfExists(tempToDelete); } catch (IOException ignore) {}
            }
        }
    }

    /**
     * Returns {databasePath, tempSnapshotOrNull}. A .db/.sqlite is used in place;
     * a .sql dump is materialized once into a private temp database.
     */
    static Path[] resolveSource(String source) throws IOException, SQLException {
        Path p = Paths.get(source);
        if (!Files.exists(p)) throw new IOException("source not found: " + source);
        if (Files.isDirectory(p)) throw new IOException("source is a directory: " + source);

        String lower = source.toLowerCase();
        if (lower.endsWith(".sql")) {
            Path snapshot = loadSQLDump(p);
            return new Path[]{snapshot, snapshot};
        }
        return new Path[]{p, null};
    }

    /**
     * One-time load of a .sql dump into a fresh temp database. This is the ONLY
     * write the program performs; it targets a temp file, never the source, and
     * completes before any worker runs.
     */
    static Path loadSQLDump(Path sqlPath) throws IOException, SQLException {
        String script = Files.readString(sqlPath);
        Path tmp = Files.createTempFile("repo-snapshot-", ".db");
        // Writable handle used only for the load, then discarded.
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + tmp.toString());
             Statement st = c.createStatement()) {
            st.execute("PRAGMA foreign_keys = OFF");
            for (String stmt : splitSql(script)) {
                st.execute(stmt);
            }
        }
        // stderr, not stdout: -json mode requires stdout to carry only the JSON object.
        System.err.println("(loaded .sql dump into private read-only snapshot: " + tmp + ")");
        return tmp;
    }

    /**
     * Quote/comment/compound-aware SQL splitter. Handles:
     *   - single-quoted string literals with '' escaping (the generator escapes
     *     quotes that way), so semicolons inside literal text are safe;
     *   - -- line comments, so semicolons inside comments are safe;
     *   - BEGIN ... END; trigger bodies, whose inner ';' must NOT split the
     *     statement (tracked via a BEGIN/END depth counter).
     */
    static List<String> splitSql(String script) {
        List<String> out = new ArrayList<>();
        StringBuilder buf = new StringBuilder();
        boolean inStr = false;
        int depth = 0; // BEGIN/END nesting (SQLite trigger bodies)
        int n = script.length();
        for (int i = 0; i < n; i++) {
            char ch = script.charAt(i);
            if (inStr) {
                buf.append(ch);
                if (ch == '\'') {
                    if (i + 1 < n && script.charAt(i + 1) == '\'') { // escaped quote
                        buf.append('\'');
                        i++;
                    } else {
                        inStr = false;
                    }
                }
                continue;
            }
            if (ch == '\'') { inStr = true; buf.append(ch); continue; }
            if (ch == '-' && i + 1 < n && script.charAt(i + 1) == '-') { // line comment
                buf.append(ch);
                i++;
                buf.append('-');
                while (i + 1 < n && script.charAt(i + 1) != '\n') { buf.append(script.charAt(++i)); }
                continue;
            }
            // Word boundary: pick up BEGIN / END keywords to track trigger bodies.
            if (isIdentChar(ch) && (i == 0 || !isIdentChar(script.charAt(i - 1)))) {
                int j = i;
                while (j < n && isIdentChar(script.charAt(j))) j++;
                String word = script.substring(i, j);
                buf.append(word);
                String up = word.toUpperCase();
                if (up.equals("BEGIN")) {
                    depth++;
                } else if (up.equals("END")) {
                    if (depth > 0) depth--;
                }
                i = j - 1;
                continue;
            }
            if (ch == ';' && depth == 0) {
                if (!stripToStatement(buf.toString()).isEmpty()) out.add(buf.toString().trim());
                buf.setLength(0);
                continue;
            }
            buf.append(ch);
        }
        if (!stripToStatement(buf.toString()).isEmpty()) out.add(buf.toString().trim());
        return out;
    }

    static boolean isIdentChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_';
    }

    /** Removes -- comment lines and whitespace to decide if a chunk has real SQL. */
    static String stripToStatement(String chunk) {
        StringBuilder sb = new StringBuilder();
        for (String line : chunk.split("\n")) {
            String t = line.strip();
            if (t.isEmpty() || t.startsWith("--")) continue;
            sb.append(t).append(' ');
        }
        return sb.toString().trim();
    }

    /** Opens a strictly read-only connection to the database. */
    static Connection openReadOnly(Path dbPath) throws SQLException {
        // The property keys below are the documented sqlite-jdbc pragma/open-mode
        // keys; open_mode=1 opens the file SQLITE_OPEN_READONLY.
        Properties props = new Properties();
        props.setProperty("open_mode", "1");          // 1 = SQLITE_OPEN_READONLY
        props.setProperty("query_only", "true");      // reject writes at the engine
        props.setProperty("busy_timeout", "5000");
        Connection c = DriverManager.getConnection("jdbc:sqlite:" + dbPath.toString(), props);
        c.setAutoCommit(true);                        // never hold a writable txn
        return c;
    }

    /** Proves the handle cannot mutate: a write MUST be rejected. */
    static void verifyReadOnly(Path dbPath) throws SQLException {
        try (Connection c = openReadOnly(dbPath); Statement st = c.createStatement()) {
            try {
                st.executeUpdate("CREATE TABLE __readonly_canary__ (x INTEGER)");
                throw new SQLException("write canary SUCCEEDED — database is NOT read-only, aborting");
            } catch (SQLException expected) {
                if (expected.getMessage() != null && expected.getMessage().contains("NOT read-only")) {
                    throw expected; // re-throw our own abort
                }
                // Expected: the driver rejected the write. Good.
            }
        }
    }

    /**
     * Returns the names of the analysis VIEW objects present in the database
     * (built from src/views/catalog.py). This replaces the previously hard-coded
     * query catalog: the workers read whatever views are installed.
     */
    static List<String> installedViews(Path dbPath) throws SQLException {
        List<String> names = new ArrayList<>();
        try (Connection c = openReadOnly(dbPath);
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery("SELECT name FROM sqlite_master WHERE type = 'view' ORDER BY name")) {
            while (rs.next()) names.add(rs.getString(1));
        }
        return names;
    }

    /**
     * Reads one installed view and returns {renderedBody, rowCountAsString}. The
     * view name comes from the database's own catalog, so the identifier is
     * trusted; it is still double-quoted for correctness.
     */
    static String[] runView(Path dbPath, String viewName) throws SQLException {
        String query = "SELECT * FROM \"" + viewName.replace("\"", "\"\"") + "\"";
        try (Connection c = openReadOnly(dbPath);
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(query)) {
            ResultSetMetaData md = rs.getMetaData();
            int cols = md.getColumnCount();
            StringBuilder sb = new StringBuilder();
            for (int i = 1; i <= cols; i++) {
                if (i > 1) sb.append(" | ");
                sb.append(md.getColumnLabel(i));
            }
            sb.append('\n');
            int count = 0;
            while (rs.next()) {
                if (count < MAX_ROWS) {
                    for (int i = 1; i <= cols; i++) {
                        if (i > 1) sb.append(" | ");
                        String val = rs.getString(i);
                        sb.append(val == null ? "NULL" : val);
                    }
                    sb.append('\n');
                } else if (count == MAX_ROWS) {
                    sb.append("... (row output truncated)\n");
                }
                count++;
            }
            return new String[]{sb.toString(), Integer.toString(count)};
        }
    }

    // ------------------------------------------------------------------
    // Machine-readable (JSON) path -- consumed by src/views/native_reader.py
    // ------------------------------------------------------------------

    /** One view read into structured form (or an error). */
    record ViewData(String view, List<String> columns, List<List<Object>> rows, String error) {}

    /**
     * Reads the requested views concurrently and writes a single JSON object
     * {"engine","views":{name:{columns,rows}},"errors":{name:msg}} to stdout.
     */
    static void emitJson(Path dbPath, List<String> viewNames, String viewsCsv,
                         int workers, int limit) throws Exception {
        Set<String> wanted = parseCsvSet(viewsCsv); // empty => all
        List<String> targets = new ArrayList<>();
        for (String v : viewNames) {
            if (wanted.isEmpty() || wanted.contains(v)) targets.add(v);
        }

        ExecutorService pool = Executors.newFixedThreadPool(Math.max(1, workers));
        List<Future<ViewData>> futures = new ArrayList<>();
        for (String v : targets) {
            futures.add(pool.submit((Callable<ViewData>) () -> readViewStructured(dbPath, v, limit)));
        }
        pool.shutdown();
        List<ViewData> datas = new ArrayList<>();
        for (Future<ViewData> f : futures) datas.add(f.get());

        StringBuilder views = new StringBuilder();
        StringBuilder errs = new StringBuilder();
        boolean firstV = true, firstE = true;
        for (ViewData d : datas) {
            if (d.error() != null) {
                if (!firstE) errs.append(',');
                firstE = false;
                appendJsonString(errs, d.view());
                errs.append(':');
                appendJsonString(errs, d.error());
                continue;
            }
            if (!firstV) views.append(',');
            firstV = false;
            appendJsonString(views, d.view());
            views.append(":{\"columns\":[");
            for (int i = 0; i < d.columns().size(); i++) {
                if (i > 0) views.append(',');
                appendJsonString(views, d.columns().get(i));
            }
            views.append("],\"rows\":[");
            for (int r = 0; r < d.rows().size(); r++) {
                if (r > 0) views.append(',');
                views.append('[');
                List<Object> row = d.rows().get(r);
                for (int c = 0; c < row.size(); c++) {
                    if (c > 0) views.append(',');
                    appendJsonValue(views, row.get(c));
                }
                views.append(']');
            }
            views.append("]}");
        }

        StringBuilder out = new StringBuilder();
        out.append("{\"engine\":\"java\",\"views\":{").append(views)
           .append("},\"errors\":{").append(errs).append("}}");
        System.out.println(out);
    }

    /** Reads one view into (columns, rows); byte[] cells become strings. */
    static ViewData readViewStructured(Path dbPath, String viewName, int limit) {
        String query = "SELECT * FROM \"" + viewName.replace("\"", "\"\"") + "\"";
        if (limit > 0) query += " LIMIT " + limit;
        try (Connection c = openReadOnly(dbPath);
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(query)) {
            ResultSetMetaData md = rs.getMetaData();
            int cols = md.getColumnCount();
            List<String> columns = new ArrayList<>();
            for (int i = 1; i <= cols; i++) columns.add(md.getColumnLabel(i));
            List<List<Object>> rows = new ArrayList<>();
            while (rs.next()) {
                List<Object> row = new ArrayList<>();
                for (int i = 1; i <= cols; i++) {
                    Object v = rs.getObject(i);
                    if (v instanceof byte[] b) v = new String(b);
                    row.add(v);
                }
                rows.add(row);
            }
            return new ViewData(viewName, columns, rows, null);
        } catch (Exception ex) {
            return new ViewData(viewName, null, null, ex.getMessage());
        }
    }

    static Set<String> parseCsvSet(String csv) {
        Set<String> set = new HashSet<>();
        if (csv != null) {
            for (String p : csv.split(",")) {
                String t = p.strip();
                if (!t.isEmpty()) set.add(t);
            }
        }
        return set;
    }

    static void appendJsonString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (ch < 0x20) sb.append(String.format("\\u%04x", (int) ch));
                    else sb.append(ch);
                }
            }
        }
        sb.append('"');
    }

    static void appendJsonValue(StringBuilder sb, Object v) {
        if (v == null) { sb.append("null"); return; }
        if (v instanceof Number || v instanceof Boolean) { sb.append(v.toString()); return; }
        appendJsonString(sb, v.toString());
    }

    static String indent(String body) {
        StringBuilder sb = new StringBuilder();
        for (String line : body.strip().split("\n")) {
            sb.append("        ").append(line).append('\n');
        }
        return sb.toString();
    }
}
