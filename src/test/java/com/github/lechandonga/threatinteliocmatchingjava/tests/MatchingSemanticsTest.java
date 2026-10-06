package com.github.lechandonga.threatinteliocmatchingjava.tests;

import com.github.lechandonga.threatinteliocmatchingjava.match.Evidence;
import com.github.lechandonga.threatinteliocmatchingjava.match.MatchStatus;
import com.github.lechandonga.threatinteliocmatchingjava.match.TelemetryResult;
import com.github.lechandonga.threatinteliocmatchingjava.tests.coverage.BusinessTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@BusinessTest("IOC 匹配语义：子域名/相似域名与 CIDR 网段边界")
class MatchingSemanticsTest {

    private static final String FEED = """
            {"indicators":[
              {"type":"domain","value":"evil-example.com","verdict":"malicious","firstSeen":"2026-09-01T00:00:00Z"},
              {"type":"cidr","value":"10.10.0.0/16","verdict":"malicious","firstSeen":"2026-09-01T00:00:00Z"},
              {"type":"ip","value":"198.51.100.5","verdict":"malicious","firstSeen":"2026-09-01T00:00:00Z"},
              {"type":"sha256",
               "value":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
               "verdict":"malicious","firstSeen":"2026-09-01T00:00:00Z"}
            ]}
            """;

    private TestSupport.Harness loaded(Path dir) throws Exception {
        TestSupport.Harness h = TestSupport.harness(dir, 600, "s:1:f.json:" + FEED);
        h.intel().refresh();
        return h;
    }

    @Test
    @DisplayName("子域名命中父域，matchKind 标记为 SUBDOMAIN_OF_INDICATOR_DOMAIN")
    void subdomainHitsParent(@TempDir Path dir) throws Exception {
        TelemetryResult result = loaded(dir).match().matchBatch("b",
                List.of(TestSupport.event("h", "www.evil-example.com"))).get(0);
        assertSame(MatchStatus.MATCH, result.status());
        assertEquals("evil-example.com", result.evidence().get(0).iocValue());
        assertEquals("SUBDOMAIN_OF_INDICATOR_DOMAIN", result.evidence().get(0).matchKind());
    }

    @Test
    @DisplayName("相似域名必须隔离：notevil-example.com / evil-example.com.evil.net / evil-example.org 全部 NO_MATCH")
    void lookalikeDomainsMustNotMatch(@TempDir Path dir) throws Exception {
        TestSupport.Harness h = loaded(dir);
        for (String lookalike : List.of(
                "notevil-example.com",
                "evil-example.com.evil.net",
                "evil-example.org",
                "evilexample.com",
                "xevil-example.com")) {
            assertSame(MatchStatus.NO_MATCH, h.match().matchBatch("b-" + lookalike,
                    List.of(TestSupport.event("h", lookalike))).get(0).status(),
                    "lookalike must not match: " + lookalike);
        }
    }

    @Test
    @DisplayName("CIDR 网段边界：网段首尾地址命中，相邻 /24 边界外地址不命中")
    void cidrBoundaries(@TempDir Path dir) throws Exception {
        TestSupport.Harness h = loaded(dir);
        assertEquals(MatchStatus.MATCH, h.match().matchBatch("b1",
                List.of(TestSupport.event("h", "10.10.0.0"))).get(0).status());
        assertEquals(MatchStatus.MATCH, h.match().matchBatch("b2",
                List.of(TestSupport.event("h", "10.10.255.255"))).get(0).status());
        assertEquals(MatchStatus.NO_MATCH, h.match().matchBatch("b3",
                List.of(TestSupport.event("h", "10.11.0.0"))).get(0).status());
        assertEquals(MatchStatus.NO_MATCH, h.match().matchBatch("b4",
                List.of(TestSupport.event("h", "10.9.255.255"))).get(0).status());
        assertEquals("IP_WITHIN_INDICATOR_CIDR", h.match().matchBatch("b5",
                        List.of(TestSupport.event("h", "10.10.1.2")))
                .get(0).evidence().get(0).matchKind());
    }

    @Test
    @DisplayName("单 IP 与 CIDR 同时命中时两条情报依据都要完整列出")
    void multipleHitsListed(@TempDir Path dir) throws Exception {
        String json = """
                {"indicators":[
                  {"type":"ip","value":"10.10.5.5","verdict":"malicious","firstSeen":"2026-09-02T00:00:00Z"},
                  {"type":"cidr","value":"10.10.0.0/16","verdict":"suspicious","firstSeen":"2026-09-01T00:00:00Z"}
                ]}
                """;
        TestSupport.Harness h = TestSupport.harness(dir, 600, "s:1:f.json:" + json);
        h.intel().refresh();

        TelemetryResult result = h.match().matchBatch("b",
                List.of(TestSupport.event("h", "10.10.5.5"))).get(0);
        assertSame(MatchStatus.MATCH, result.status());
        assertEquals(2, result.evidence().stream().map(Evidence::iocValue).distinct().count());
    }

    @Test
    @DisplayName("哈希精确匹配，大小写归一；错误长度/字符的遥测按记录拒绝")
    void hashExactAndRejection(@TempDir Path dir) throws Exception {
        TestSupport.Harness h = loaded(dir);
        assertSame(MatchStatus.MATCH, h.match().matchBatch("b1",
                List.of(TestSupport.event("h",
                        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")))
                .get(0).status());
        TelemetryResult bad = h.match().matchBatch("b2",
                List.of(TestSupport.event("h", "abcdef012345"))).get(0);
        assertTrue(bad.rejectionReason() != null && bad.rejectionReason().contains("hex"),
                "12 位十六进制不是 md5/sha1/sha256，必须逐记录拒绝");
        assertTrue(loaded(dir).match().matchBatch("b3",
                List.of(TestSupport.event("h", "999.999.999.999"))).get(0)
                .rejectionReason().contains("invalid IPv4"));
    }
}
