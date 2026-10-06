package com.github.lechandonga.threatinteliocmatchingjava.tests;

import com.github.lechandonga.threatinteliocmatchingjava.intel.IntelSnapshot;
import com.github.lechandonga.threatinteliocmatchingjava.match.Evidence;
import com.github.lechandonga.threatinteliocmatchingjava.match.MatchStatus;
import com.github.lechandonga.threatinteliocmatchingjava.match.TelemetryResult;
import com.github.lechandonga.threatinteliocmatchingjava.model.IocType;
import com.github.lechandonga.threatinteliocmatchingjava.tests.coverage.BusinessTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@BusinessTest("情报冲突的确定性取舍")
class ConflictResolutionTest {

    private static final String HASH =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    private static final String LOW_JSON = """
            {"indicators":[
              {"type":"sha256","value":"%s","verdict":"malicious","firstSeen":"2026-09-01T00:00:00Z"}
            ]}
            """.formatted(HASH);

    private static final String HIGH_JSON = """
            {"indicators":[
              {"type":"sha256","value":"%s","verdict":"malicious","firstSeen":"2026-09-20T00:00:00Z"}
            ]}
            """.formatted(HASH);

    private static final String CLEAN_JSON = """
            {"indicators":[
              {"type":"sha256","value":"%s","verdict":"clean","firstSeen":"2026-08-01T00:00:00Z"}
            ]}
            """.formatted(HASH);

    @Test
    @DisplayName("判定等级优先：低优先级来源的 MALICIOUS 仍胜过高优先级来源的 CLEAN")
    void verdictRankBeatsSourcePriority(@TempDir Path dir) throws Exception {
        TestSupport.Harness h = TestSupport.harness(dir, 600,
                "low:10:low.json:" + LOW_JSON,
                "high:99:high.json:" + CLEAN_JSON);
        h.intel().refresh();

        List<TelemetryResult> results = h.match().matchBatch("b1",
                List.of(TestSupport.event("host-1", HASH)));

        assertSame(MatchStatus.MATCH, results.get(0).status());
        assertEquals("malicious", results.get(0).effectiveVerdict());
    }

    @Test
    @DisplayName("同等级时按来源 priority 取舍，结果可从 winner 依据中看出")
    void sameVerdictHigherPriorityWins(@TempDir Path dir) throws Exception {
        TestSupport.Harness h = TestSupport.harness(dir, 600,
                "low:10:low.json:" + LOW_JSON.replace("malicious", "suspicious"),
                "high:20:high.json:" + HIGH_JSON.replace("malicious", "suspicious"));
        h.intel().refresh();

        IntelSnapshot snapshot = h.intel().snapshot();
        assertEquals("high", snapshot.exact(IocType.HASH_SHA256, HASH).winner().sourceId());

        List<TelemetryResult> results = h.match().matchBatch("b1",
                List.of(TestSupport.event("host-1", HASH)));
        List<Evidence> evidence = results.get(0).evidence();
        assertEquals(2, evidence.size(), "两条来源依据都要列出");
        Evidence winner = evidence.stream().filter(Evidence::conflictWinner).findFirst().orElseThrow();
        assertEquals("high", winner.sourceId());
        assertEquals(20, winner.sourcePriority());
    }

    @Test
    @DisplayName("同等级同优先级时 firstSeen 更早者胜，再相同则 sourceId 字典序优先")
    void tieBreaksAreDeterministic(@TempDir Path dir) throws Exception {
        String newer = """
                {"indicators":[
                  {"type":"sha256","value":"%s","verdict":"suspicious","firstSeen":"2026-09-20T00:00:00Z"}
                ]}
                """.formatted(HASH);
        String older = """
                {"indicators":[
                  {"type":"sha256","value":"%s","verdict":"suspicious","firstSeen":"2026-09-01T00:00:00Z"}
                ]}
                """.formatted(HASH);
        TestSupport.Harness h = TestSupport.harness(dir, 600,
                "zeta:10:zeta.json:" + newer,
                "alpha:10:alpha.json:" + older);
        h.intel().refresh();
        assertEquals("alpha", h.intel().snapshot().exact(IocType.HASH_SHA256, HASH).winner().sourceId());

        TestSupport.Harness h2 = TestSupport.harness(dir, 600,
                "zeta:10:z.json:" + older,
                "alpha:10:a.json:" + older);
        h2.intel().refresh();
        assertTrue("alpha".equals(h2.intel().snapshot()
                .exact(IocType.HASH_SHA256, HASH).winner().sourceId()));
    }
}
