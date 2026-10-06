package com.github.lechandonga.threatinteliocmatchingjava.tests;

import com.github.lechandonga.threatinteliocmatchingjava.intel.SourceLoadResult;
import com.github.lechandonga.threatinteliocmatchingjava.match.MatchStatus;
import com.github.lechandonga.threatinteliocmatchingjava.tests.coverage.BusinessTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@BusinessTest("情报源失败容错与逐行拒绝原因")
class SourceFailureTest {

    private static final String GOOD_JSON = """
            {"indicators":[
              {"type":"domain","value":"good-source.test","verdict":"malicious","firstSeen":"2026-09-01T00:00:00Z"}
            ]}
            """;

    @Test
    @DisplayName("来源文件缺失导致整体失败时，该源旧数据保留，其他源正常更新")
    void failedSourceKeepsPreviousData(@TempDir Path dir) throws Exception {
        Path good = dir.resolve("good.json");
        Path gone = dir.resolve("gone.json");
        Files.writeString(good, GOOD_JSON);
        Files.writeString(gone, """
                {"indicators":[
                  {"type":"domain","value":"gone-source.test","verdict":"malicious","firstSeen":"2026-09-01T00:00:00Z"}
                ]}
                """);

        TestSupport.Harness h = TestSupport.harness(dir, 600,
                "good:1:" + good.getFileName() + ":" + GOOD_JSON,
                "gone:2:" + gone.getFileName() + ":" + Files.readString(gone));
        h.intel().refresh();
        assertEquals(2, h.intel().snapshot().recordCount());

        Files.delete(gone);
        var report = h.intel().refresh();
        assertFalse(report.complete());
        SourceLoadResult goneResult = report.sources().stream()
                .filter(s -> s.sourceId().equals("gone")).findFirst().orElseThrow();
        assertFalse(goneResult.success());
        assertTrue(goneResult.fatalError().contains("previous data retained"));

        assertEquals(2, h.intel().snapshot().recordCount(), "失败源的已生效情报不得被清空");
        assertSame(MatchStatus.MATCH, h.match().matchBatch("b",
                List.of(TestSupport.event("a", "gone-source.test"))).get(0).status());
        assertSame(MatchStatus.MATCH, h.match().matchBatch("b2",
                List.of(TestSupport.event("a", "good-source.test"))).get(0).status());
    }

    @Test
    @DisplayName("结构损坏（非法 JSON）按源整体失败处理，而不是悄悄清空")
    void corruptJsonIsFatal(@TempDir Path dir) throws Exception {
        TestSupport.Harness h = TestSupport.harness(dir, 600,
                "bad:1:f.json:" + GOOD_JSON);
        h.intel().refresh();
        Files.writeString(dir.resolve("f.json"), "{ this is not json");
        var report = h.intel().refresh();
        assertFalse(report.sources().get(0).success());
        assertEquals(1, h.intel().snapshot().recordCount());
    }

    @Test
    @DisplayName("格式错误的记录逐条拒绝，给出行号与可区分原因，其余记录照常生效")
    void perRecordReasons(@TempDir Path dir) throws Exception {
        String csv = """
                # header comment
                domain|valid.example|malicious|||||
                weirdtype|weird.example|malicious|||||
                domain|no_tld|malicious|||||
                cidr|10.0.0.5/24|malicious|||||
                domain|edge.example|not-a-verdict|||||
                ip|10.0.0.1|malicious|||||
                """;
        TestSupport.Harness h = TestSupport.harness(dir, 600, "s:1:f.csv:" + csv);
        var report = h.intel().refresh();
        SourceLoadResult result = report.sources().get(0);
        assertTrue(result.success());
        assertEquals(2, result.accepted());
        assertEquals(4, result.rejected().size());
        List<String> reasons = result.rejected().stream().map(r -> r.reason()).toList();
        assertTrue(reasons.stream().anyMatch(r -> r.contains("unknown indicator type")));
        assertTrue(reasons.stream().anyMatch(r -> r.contains("TLD")));
        assertTrue(reasons.stream().anyMatch(r -> r.contains("non-canonical CIDR")));
        assertTrue(reasons.stream().anyMatch(r -> r.contains("unknown verdict")));

        assertSame(MatchStatus.MATCH, h.match().matchBatch("b",
                List.of(TestSupport.event("a", "valid.example"))).get(0).status());
    }
}
