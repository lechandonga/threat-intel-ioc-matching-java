package com.github.lechandonga.threatinteliocmatchingjava.tests;

import com.github.lechandonga.threatinteliocmatchingjava.alert.AlertRecord;
import com.github.lechandonga.threatinteliocmatchingjava.alert.AlertService;
import com.github.lechandonga.threatinteliocmatchingjava.config.IntelSourceProperties;
import com.github.lechandonga.threatinteliocmatchingjava.intel.IntelService;
import com.github.lechandonga.threatinteliocmatchingjava.normalize.CsvFeedParser;
import com.github.lechandonga.threatinteliocmatchingjava.normalize.JsonFeedParser;
import com.github.lechandonga.threatinteliocmatchingjava.normalize.StixBundleParser;
import com.github.lechandonga.threatinteliocmatchingjava.tests.coverage.BusinessTest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

@BusinessTest("告警抑制窗口与批次幂等")
class SuppressionAndDedupTest {

    private static final String FEED = """
            {"indicators":[
              {"type":"domain","value":"evil.test","verdict":"malicious","firstSeen":"2026-09-01T00:00:00Z"},
              {"type":"domain","value":"other.test","verdict":"malicious","firstSeen":"2026-09-01T00:00:00Z"}
            ]}
            """;

    /** 可推进的时钟，用于验证窗口随时间滚动。 */
    private static final class MutableClock extends Clock {
        private Instant now = TestSupport.NOW;

        void advanceSeconds(long seconds) {
            now = now.plusSeconds(seconds);
        }

        @Override public ZoneId getZone() { return ZoneId.of("UTC"); }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }

    @Test
    @DisplayName("抑制窗口内同一资产+同一 IOC 只产生一条告警，命中次数与时间范围累计")
    void suppressWithinWindow(@TempDir Path dir) throws Exception {
        TestSupport.Harness h = TestSupport.harness(dir, 600, "s:1:f.json:" + FEED);
        h.intel().refresh();

        h.match().matchBatch("b1", List.of(
                TestSupport.event("host-1", "evil.test", "2026-10-07T00:00:00Z"),
                TestSupport.event("host-1", "other.test", "2026-10-07T00:01:00Z")));
        h.match().matchBatch("b2", List.of(
                TestSupport.event("host-1", "evil.test", "2026-10-07T00:05:00Z"),
                TestSupport.event("host-2", "evil.test", "2026-10-07T00:05:30Z")));

        List<AlertRecord> alerts = h.alerts().query(null, null, null);
        assertEquals(3, alerts.size(), "不同 IOC、不同资产分别独立抑制");
        AlertRecord host1Evil = alerts.stream()
                .filter(a -> a.assetId().equals("host-1") && a.iocValue().equals("evil.test"))
                .findFirst().orElseThrow();
        assertEquals(2, host1Evil.hitCount());
        assertEquals(Instant.parse("2026-10-07T00:00:00Z"), host1Evil.firstSeen());
        assertEquals(Instant.parse("2026-10-07T00:05:00Z"), host1Evil.lastSeen());
        assertEquals(List.of("b1", "b2"), host1Evil.batchIds());
    }

    @Test
    @DisplayName("同一批次重复投递不产生重复告警、不重复计数")
    void duplicateBatchIsIdempotent(@TempDir Path dir) throws Exception {
        TestSupport.Harness h = TestSupport.harness(dir, 600, "s:1:f.json:" + FEED);
        h.intel().refresh();

        var batch = List.of(TestSupport.event("host-1", "evil.test", "2026-10-07T00:00:00Z"));
        h.match().matchBatch("dup-batch", batch);
        h.match().matchBatch("dup-batch", batch);
        h.match().matchBatch("dup-batch", batch);

        List<AlertRecord> alerts = h.alerts().query("host-1", "evil.test", null);
        assertEquals(1, alerts.size());
        assertEquals(1, alerts.get(0).hitCount());
    }

    @Test
    @DisplayName("超过抑制窗口后的命中开启新窗口，产生新告警")
    void newWindowAfterExpiry(@TempDir Path dir) throws Exception {
        MutableClock clock = new MutableClock();
        ObjectMapper mapper = new ObjectMapper();
        IntelSourceProperties props = new IntelSourceProperties();
        props.setLoadOnStartup(false);
        props.setSuppressionWindowSeconds(600);
        IntelSourceProperties.Source source = new IntelSourceProperties.Source();
        source.setId("s");
        source.setPriority(1);
        source.setFormat(IntelSourceProperties.Format.JSON_FEED);
        Path file = dir.resolve("f.json");
        Files.writeString(file, FEED);
        source.setPath(file);
        props.setSources(List.of(source));
        IntelService intel = new IntelService(props,
                List.of(new JsonFeedParser(mapper), new CsvFeedParser(), new StixBundleParser(mapper)), clock);
        AlertService alertSvc = new AlertService(props, clock);
        var matchSvc = new com.github.lechandonga.threatinteliocmatchingjava.match.MatchService(
                intel, alertSvc, clock);
        intel.refresh();

        matchSvc.matchBatch("b1", List.of(TestSupport.event("host-1", "evil.test")));
        clock.advanceSeconds(599);
        matchSvc.matchBatch("b2", List.of(TestSupport.event("host-1", "evil.test")));
        clock.advanceSeconds(1);
        matchSvc.matchBatch("b3", List.of(TestSupport.event("host-1", "evil.test")));

        List<AlertRecord> alerts = alertSvc.query("host-1", "evil.test", null);
        assertEquals(2, alerts.size());
        assertEquals(2, alerts.get(0).hitCount());
        assertEquals(1, alerts.get(1).hitCount());
        List<AlertRecord> open = alertSvc.query("host-1", "evil.test", true);
        assertEquals(1, open.size());
        assertEquals(1, open.get(0).hitCount(), "openOnly 只返回当前窗口仍开放的新告警");
    }
}
