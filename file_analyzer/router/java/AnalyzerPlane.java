// tabgen analysis plane (Java): a concurrent thread pool that drives per-shard
// analysis by fanning out to the Python per-shard worker (file_analyzer/router/worker.py).
//
// ROLE
//   The sibling of the Go analysis plane. The router makes the routing decision
//   in Python (staged in <temp>/mapping.json) and hands this plane a subset of
//   shard ids; the plane runs them concurrently, one child process per shard:
//
//       python worker.py --readers-root <root> --temp <temp> --shard <id>
//
//   A bounded ExecutorService runs up to -workers shards at once. The plane
//   never touches the database and never reimplements analysis — it is a
//   concurrency driver only. Go and Java planes run at the same wall-clock time,
//   each over a disjoint set of shards, so the whole file corpus is analyzed in
//   parallel across both language planes.
//
// Compile:
//   javac -d out AnalyzerPlane.java
// Run:
//   java -cp out AnalyzerPlane --python python --readers-root ../../.. \
//        --temp <temp> --shards shard_schema --workers 4
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public final class AnalyzerPlane {

    private static final class ShardResult {
        final String shard;
        final boolean ok;
        final long millis;
        ShardResult(String shard, boolean ok, long millis) {
            this.shard = shard; this.ok = ok; this.millis = millis;
        }
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> opt = parseArgs(args);
        String python = opt.getOrDefault("python", "python");
        String readersRoot = opt.get("readers-root");
        String temp = opt.get("temp");
        String shardsCSV = opt.getOrDefault("shards", "");
        int workers = Integer.parseInt(opt.getOrDefault("workers",
                String.valueOf(Runtime.getRuntime().availableProcessors())));

        if (readersRoot == null || temp == null) {
            System.err.println("fatal: --readers-root and --temp are required");
            System.exit(2);
        }
        List<String> shards = splitNonEmpty(shardsCSV);
        if (shards.isEmpty()) {
            System.out.println("== analysis-plane (Java) == no shards assigned; nothing to do");
            return;
        }
        if (workers < 1) workers = 1;

        Path workerScript = Paths.get(readersRoot, "file_analyzer", "router", "worker.py");

        System.out.println("== analysis-plane (Java) ==");
        System.out.println("shards   : " + String.join(", ", shards));
        System.out.println("workers  : " + workers + " (concurrent processes)\n");

        ExecutorService pool = Executors.newFixedThreadPool(workers);
        List<Future<ShardResult>> futures = new ArrayList<>();
        final String py = python;
        final String root = readersRoot;
        final String tmp = temp;
        for (final String shard : shards) {
            Callable<ShardResult> task = () -> {
                long start = System.nanoTime();
                boolean ok = runWorker(py, workerScript.toString(), root, tmp, shard);
                long ms = (System.nanoTime() - start) / 1_000_000L;
                return new ShardResult(shard, ok, ms);
            };
            futures.add(pool.submit(task));
        }
        pool.shutdown();

        int failures = 0;
        for (Future<ShardResult> f : futures) {
            ShardResult r = f.get();
            if (r.ok) {
                System.out.printf("[java] %-16s OK    (%d ms)%n", r.shard, r.millis);
            } else {
                failures++;
                System.out.printf("[java] %-16s ERROR (%d ms)%n", r.shard, r.millis);
            }
        }

        System.out.printf("%n-- plane summary --%nshards: %d  failures: %d%n", shards.size(), failures);
        if (failures > 0) System.exit(1);
    }

    // Runs one per-shard Python worker as a child process, streaming its output.
    private static boolean runWorker(String python, String script, String readersRoot,
                                     String temp, String shard) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(
                python, script,
                "--readers-root", readersRoot,
                "--temp", temp,
                "--shard", shard);
        pb.redirectErrorStream(false);
        Process proc = pb.start();
        Thread out = streamThread(proc.getInputStream(), "    ");
        Thread err = streamThread(proc.getErrorStream(), "    ! ");
        out.start();
        err.start();
        int code = proc.waitFor();
        out.join();
        err.join();
        return code == 0;
    }

    private static Thread streamThread(InputStream in, String prefix) {
        return new Thread(() -> {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    System.out.println(prefix + line);
                }
            } catch (Exception ignored) {
            }
        });
    }

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.startsWith("--") && i + 1 < args.length) {
                m.put(a.substring(2), args[++i]);
            }
        }
        return m;
    }

    private static List<String> splitNonEmpty(String csv) {
        List<String> out = new ArrayList<>();
        for (String p : csv.split(",")) {
            p = p.trim();
            if (!p.isEmpty()) out.add(p);
        }
        return out;
    }
}
