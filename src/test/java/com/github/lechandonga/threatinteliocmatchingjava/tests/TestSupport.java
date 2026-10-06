package com.github.lechandonga.threatinteliocmatchingjava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.threatinteliocmatchingjava.alert.AlertService;
import com.github.lechandonga.threatinteliocmatchingjava.config.IntelSourceProperties;
import com.github.lechandonga.threatinteliocmatchingjava.intel.IntelService;
import com.github.lechandonga.threatinteliocmatchingjava.match.MatchService;
import com.github.lechandonga.threatinteliocmatchingjava.match.TelemetryRequest;
import com.github.lechandonga.threatinteliocmatchingjava.normalize.CsvFeedParser;
import com.github.lechandonga.threatinteliocmatchingjava.normalize.JsonFeedParser;
import com.github.lechandonga.threatinteliocmatchingjava.normalize.StixBundleParser;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

/**
 * 测试夹具：在临时目录用真实解析器跑完整加载/匹配/告警链路，
 * 时钟固定为 {@code 2026-10-07T00:00:00Z}，方便构造过期/未生效边界。
 */
public final class TestSupport {

    public static final Instant NOW = Instant.parse("2026-10-07T00:00:00Z");

    private TestSupport() {
    }

    public record Harness(IntelService intel, MatchService match, AlertService alerts) {
    }

    public static Clock fixedClock() {
        return Clock.fixed(NOW, ZoneOffset.UTC);
    }

    public static Harness harness(Path dir, long windowSeconds, String... fileSpecs) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        IntelSourceProperties props = new IntelSourceProperties();
        props.setLoadOnStartup(false);
        props.setSuppressionWindowSeconds(windowSeconds);
        List<IntelSourceProperties.Source> sources = new java.util.ArrayList<>();
        for (String spec : fileSpecs) {
            String[] parts = spec.split(":", 4);
            Path file = dir.resolve(parts[2]);
            Files.writeString(file, parts[3]);
            IntelSourceProperties.Source source = new IntelSourceProperties.Source();
            source.setId(parts[0]);
            source.setPriority(Long.parseLong(parts[1]));
            source.setPath(file);
            source.setFormat(IntelSourceProperties.Format.valueOf(parts[2].endsWith(".csv")
                    ? "CSV" : parts[2].contains("stix") ? "STIX_BUNDLE" : "JSON_FEED"));
            sources.add(source);
        }
        props.setSources(sources);
        Clock clock = fixedClock();
        IntelService intel = new IntelService(props,
                List.of(new JsonFeedParser(mapper), new CsvFeedParser(), new StixBundleParser(mapper)), clock);
        AlertService alerts = new AlertService(props, clock);
        MatchService match = new MatchService(intel, alerts, clock);
        return new Harness(intel, match, alerts);
    }

    public static TelemetryRequest.Event event(String assetId, String value) {
        return event(assetId, value, null);
    }

    public static TelemetryRequest.Event event(String assetId, String value, String observedAt) {
        TelemetryRequest.Event e = new TelemetryRequest.Event();
        e.setAssetId(assetId);
        e.setValue(value);
        e.setObservedAt(observedAt);
        return e;
    }
}
