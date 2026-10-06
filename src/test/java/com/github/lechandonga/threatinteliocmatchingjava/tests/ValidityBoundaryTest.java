package com.github.lechandonga.threatinteliocmatchingjava.tests;

import com.github.lechandonga.threatinteliocmatchingjava.match.MatchStatus;
import com.github.lechandonga.threatinteliocmatchingjava.match.TelemetryResult;
import com.github.lechandonga.threatinteliocmatchingjava.tests.coverage.BusinessTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertSame;

@BusinessTest("情报有效期边界：过期/未生效与不存在严格区分")
class ValidityBoundaryTest {

    private static String feed(String validFrom, String validUntil) {
        return """
                {"indicators":[
                  {"type":"domain","value":"edge.test","verdict":"malicious",
                   "validFrom":%s,"validUntil":%s}
                ]}
                """.formatted(
                validFrom == null ? "null" : "\"" + validFrom + "\"",
                validUntil == null ? "null" : "\"" + validUntil + "\"");
    }

    @Test
    @DisplayName("validUntil 边界：恰好在到期时刻判定为 EXPIRED（区间右开），前一秒仍 MATCH")
    void expiryIsHalfOpen(@TempDir Path dir) throws Exception {
        TestSupport.Harness h = TestSupport.harness(dir, 600,
                "s:1:f.json:" + feed(null, "2026-10-07T00:00:00Z"));
        h.intel().refresh();

        assertSame(MatchStatus.EXPIRED, h.match()
                .matchBatch("b", List.of(TestSupport.event("a", "edge.test", "2026-10-07T00:00:00Z")))
                .get(0).status());
        assertSame(MatchStatus.MATCH, h.match()
                .matchBatch("b", List.of(TestSupport.event("a", "edge.test", "2026-10-06T23:59:59Z")))
                .get(0).status());
    }

    @Test
    @DisplayName("validFrom 边界：生效时刻 MATCH（区间左闭），之前为 NOT_YET_VALID")
    void notYetValidIsDistinct(@TempDir Path dir) throws Exception {
        TestSupport.Harness h = TestSupport.harness(dir, 600,
                "s:1:f.json:" + feed("2026-10-07T00:00:00Z", null));
        h.intel().refresh();

        List<TelemetryResult> future = h.match().matchBatch("b",
                List.of(TestSupport.event("a", "edge.test", "2026-10-06T23:59:59Z")));
        assertSame(MatchStatus.NOT_YET_VALID, future.get(0).status());
        assertSame(MatchStatus.MATCH, h.match().matchBatch("b2",
                List.of(TestSupport.event("a", "edge.test", "2026-10-07T00:00:00Z"))).get(0).status());
    }

    @Test
    @DisplayName("完全不存在的 IOC 是 NO_MATCH，与 EXPIRED 区分")
    void absentIsNoMatch(@TempDir Path dir) throws Exception {
        TestSupport.Harness h = TestSupport.harness(dir, 600,
                "s:1:f.json:" + feed(null, "2026-10-07T00:00:00Z"));
        h.intel().refresh();

        assertSame(MatchStatus.NO_MATCH, h.match().matchBatch("b",
                List.of(TestSupport.event("a", "never.heard.test"))).get(0).status());
    }

    @Test
    @DisplayName("同 IOC 一条过期、一条生效时结果必须为 MATCH，并同时列出两条依据")
    void oneEffectiveOneExpired(@TempDir Path dir) throws Exception {
        String json = """
                {"indicators":[
                  {"type":"domain","value":"edge.test","verdict":"malicious",
                   "validUntil":"2026-10-01T00:00:00Z","firstSeen":"2026-09-01T00:00:00Z"},
                  {"type":"domain","value":"edge.test","verdict":"suspicious",
                   "validFrom":"2026-10-05T00:00:00Z","firstSeen":"2026-10-05T00:00:00Z"}
                ]}
                """;
        TestSupport.Harness h = TestSupport.harness(dir, 600, "s:1:f.json:" + json);
        h.intel().refresh();

        TelemetryResult result = h.match().matchBatch("b",
                List.of(TestSupport.event("a", "edge.test"))).get(0);
        assertSame(MatchStatus.MATCH, result.status());
        org.junit.jupiter.api.Assertions.assertEquals(2, result.evidence().size());
        org.junit.jupiter.api.Assertions.assertEquals(1,
                result.evidence().stream().filter(com.github.lechandonga.threatinteliocmatchingjava.match.Evidence::effective).count());
    }
}
