package com.github.lechandonga.threatinteliocmatchingjava.tests;

import com.github.lechandonga.threatinteliocmatchingjava.intel.IntelSnapshot;
import com.github.lechandonga.threatinteliocmatchingjava.tests.coverage.BusinessTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertTrue;

@BusinessTest("刷新与匹配并发：查询只见完整快照")
class ConcurrentRefreshTest {

    /**
     * 刷新线程持续把文件改成 n 条记录，匹配线程读取快照计数。
     * 任何一次读到的 recordCount 必须等于该快照内部实际索引大小，
     * 即只能看到刷新前或刷新后的完整状态。
     */
    @Test
    @DisplayName("并发刷新/查询下快照始终自洽，不存在中间态")
    void snapshotsAreAlwaysConsistent(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("f.json");
        Files.writeString(file, feed(1));
        TestSupport.Harness h = TestSupport.harness(dir, 600, "s:1:f.json:x");
        h.intel().refresh();

        ExecutorService pool = Executors.newFixedThreadPool(3);
        CountDownLatch start = new CountDownLatch(1);
        Set<String> inconsistencies = ConcurrentHashMap.newKeySet();
        Set<Integer> observedCounts = ConcurrentHashMap.newKeySet();

        Runnable refresher = () -> {
            try {
                start.await();
                for (int i = 0; i < 100; i++) {
                    int n = 1 + (i % 50);
                    Files.writeString(file, feed(n));
                    h.intel().refresh();
                }
            } catch (Exception e) {
                inconsistencies.add("refresher error: " + e);
            }
        };
        Runnable reader = () -> {
            try {
                start.await();
                for (int i = 0; i < 500; i++) {
                    IntelSnapshot snapshot = h.intel().snapshot();
                    int actual = snapshot.exactIndex().values().stream()
                            .mapToInt(Map -> Map.size()).sum();
                    observedCounts.add(snapshot.recordCount());
                    if (actual != snapshot.recordCount()) {
                        inconsistencies.add("torn snapshot: declared="
                                + snapshot.recordCount() + " actual=" + actual);
                    }
                }
            } catch (Exception e) {
                inconsistencies.add("reader error: " + e);
            }
        };

        pool.submit(refresher);
        pool.submit(reader);
        pool.submit(reader);
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        assertTrue(inconsistencies.isEmpty(), "发现中间态: " + inconsistencies);
        assertTrue(observedCounts.size() > 1, "读者应观测到多个不同版本的快照");
    }

    private static String feed(int n) {
        List<String> rows = new java.util.ArrayList<>();
        for (int i = 0; i < n; i++) {
            rows.add("""
                    {"type":"domain","value":"d%d.race.test","verdict":"malicious","firstSeen":"2026-09-01T00:00:00Z"}
                    """.formatted(i));
        }
        return "{\"indicators\":[" + String.join(",", rows) + "]}";
    }
}
