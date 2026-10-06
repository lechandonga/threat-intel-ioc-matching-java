package com.github.lechandonga.threatinteliocmatchingjava.intel;

import com.github.lechandonga.threatinteliocmatchingjava.config.IntelSourceProperties;
import com.github.lechandonga.threatinteliocmatchingjava.model.IocRecord;
import com.github.lechandonga.threatinteliocmatchingjava.model.IocType;
import com.github.lechandonga.threatinteliocmatchingjava.model.SourceRef;
import com.github.lechandonga.threatinteliocmatchingjava.net.IpCidr;
import com.github.lechandonga.threatinteliocmatchingjava.normalize.IntelSourceParser;
import com.github.lechandonga.threatinteliocmatchingjava.normalize.Normalize;
import com.github.lechandonga.threatinteliocmatchingjava.normalize.ParsedIoc;
import com.github.lechandonga.threatinteliocmatchingjava.normalize.Times;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 情报库生命周期管理：加载多源、逐条校验归一、冲突裁决、
 * 不可变快照构建与原子发布。单个来源整体失败时保留该源在上一版
 * 快照中的数据，绝不影响其他来源，也不会清空已生效情报。
 */
@Service
public class IntelService {

    private static final Logger log = LoggerFactory.getLogger(IntelService.class);

    private final IntelSourceProperties properties;
    private final Map<IntelSourceProperties.Format, IntelSourceParser> parsers;
    private final Clock clock;
    private final AtomicReference<IntelSnapshot> snapshot;

    public IntelService(IntelSourceProperties properties, List<IntelSourceParser> parserList, Clock clock) {
        this.properties = properties;
        this.parsers = new EnumMap<>(IntelSourceProperties.Format.class);
        parserList.forEach(p -> parsers.put(p.format(), p));
        this.clock = clock;
        this.snapshot = new AtomicReference<>(emptySnapshot());
    }

    @PostConstruct
    void loadOnStartup() {
        if (properties.isLoadOnStartup()) {
            try {
                refresh();
            } catch (Exception e) {
                log.warn("startup intel load failed, running with empty snapshot: {}", e.getMessage());
            }
        }
    }

    public IntelSnapshot snapshot() {
        return snapshot.get();
    }

    /**
     * 重新加载全部情报源并原子发布新快照。刷新期间进行的匹配
     * 仍读旧快照；新快照构建完成后一次性切换。
     */
    public synchronized RefreshReport refresh() {
        IntelSnapshot previous = snapshot.get();
        Map<String, List<SourceRef>> grouped = new HashMap<>();
        Map<String, SourceLoadResult> results = new LinkedHashMap<>();
        boolean complete = true;

        for (IntelSourceProperties.Source source : properties.getSources()) {
            SourceLoadResult result = loadOne(source, grouped, previous);
            results.put(source.getId(), result);
            if (!result.success()) {
                complete = false;
            }
        }

        IntelSnapshot next = buildSnapshot(grouped, results);
        snapshot.set(next);
        log.info("intel refresh published: {} iocs, {} sources, complete={}",
                next.recordCount(), results.size(), complete);
        return new RefreshReport(Instant.now(clock), complete, next.recordCount(), List.copyOf(results.values()));
    }

    /**
     * 加载单个来源：整体失败（文件缺失/不可读/结构损坏）时从上一版快照
     * 取回该来源的记录，保证已生效情报不被清空。
     */
    private SourceLoadResult loadOne(IntelSourceProperties.Source source,
                                     Map<String, List<SourceRef>> grouped,
                                     IntelSnapshot previous) {
        IntelSourceParser parser = parsers.get(source.getFormat());
        if (parser == null) {
            return keepPrevious(source, grouped, previous, "no parser for format " + source.getFormat());
        }
        if (!Files.isRegularFile(source.getPath())) {
            return keepPrevious(source, grouped, previous,
                    "source file not found: " + source.getPath().toAbsolutePath());
        }
        List<ParsedIoc> parsed;
        try {
            parsed = parser.parse(source.getPath());
        } catch (NoSuchFileException e) {
            return keepPrevious(source, grouped, previous, "source file vanished: " + e.getMessage());
        } catch (IOException | UncheckedIOException e) {
            return keepPrevious(source, grouped, previous, "source unreadable/corrupt: " + e.getMessage());
        }

        List<RejectedRecord> rejected = new ArrayList<>();
        int accepted = 0;
        for (ParsedIoc row : parsed) {
            try {
                IocType type = mapType(row.rawType());
                Normalize.NormValue normalized = Normalize.normalize(type, row.rawValue());
                Instant validFrom = Times.parse(row.validFrom(), "validFrom", row.line());
                Instant validUntil = Times.parse(row.validUntil(), "validUntil", row.line());
                Instant firstSeen = Times.parse(row.firstSeen(), "firstSeen", row.line());
                if (validFrom != null && validUntil != null && !validFrom.isBefore(validUntil)) {
                    throw new IllegalArgumentException(
                            "line " + row.line() + ": validFrom must be before validUntil");
                }
                SourceRef ref = new SourceRef(source.getId(), source.getPriority(),
                        VerdictParser.parse(row.verdict(), row.line()),
                        row.severity(), validFrom, validUntil,
                        firstSeen != null ? firstSeen : Instant.now(clock),
                        row.description(), row.line());
                grouped.computeIfAbsent(key(normalized.type(), normalized.value()), k -> new ArrayList<>()).add(ref);
                accepted++;
            } catch (IllegalArgumentException e) {
                rejected.add(new RejectedRecord(row.line(), abbreviate(row.rawLine()), e.getMessage()));
            }
        }
        log.info("source '{}' loaded: {} accepted, {} rejected", source.getId(), accepted, rejected.size());
        return SourceLoadResult.loaded(source.getId(), accepted, rejected);
    }

    private SourceLoadResult keepPrevious(IntelSourceProperties.Source source,
                                          Map<String, List<SourceRef>> grouped,
                                          IntelSnapshot previous, String error) {
        int kept = 0;
        for (Map<IocType, Map<String, IocRecord>> byType : List.of(previous.exactIndex())) {
            for (Map<String, IocRecord> records : byType.values()) {
                for (IocRecord record : records.values()) {
                    for (SourceRef ref : record.sources()) {
                        if (ref.sourceId().equals(source.getId())) {
                            grouped.computeIfAbsent(key(record.type(), record.value()),
                                    k -> new ArrayList<>()).add(ref);
                            kept++;
                        }
                    }
                }
            }
        }
        log.warn("source '{}' FAILED ({}); kept {} previously loaded refs from it",
                source.getId(), error, kept);
        return SourceLoadResult.failed(source.getId(), error + (kept > 0
                ? " (previous data retained: " + kept + " refs)"
                : " (no previous data for this source)"));
    }

    private static String abbreviate(String raw) {
        if (raw == null) {
            return "";
        }
        return raw.length() <= 300 ? raw : raw.substring(0, 300) + "...";
    }

    private static String key(IocType type, String value) {
        return type.name() + "|" + value;
    }

    private static IocType mapType(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("indicator type is empty");
        }
        return switch (raw.trim().toLowerCase().replace("_", "-").replace(" ", "")) {
            case "sha256", "sha-256" -> IocType.HASH_SHA256;
            case "sha1", "sha-1" -> IocType.HASH_SHA1;
            case "md5" -> IocType.HASH_MD5;
            case "domain", "domain-name", "hostname" -> IocType.DOMAIN;
            case "ip", "ipv4", "ipv4-addr" -> IocType.IP;
            case "cidr", "cidr4", "ipv4-cidr" -> IocType.CIDR;
            default -> throw new IllegalArgumentException("unknown indicator type: " + raw);
        };
    }

    private IntelSnapshot buildSnapshot(Map<String, List<SourceRef>> grouped,
                                        Map<String, SourceLoadResult> results) {
        Map<IocType, Map<String, IocRecord>> exact = new EnumMap<>(IocType.class);
        for (IocType type : IocType.values()) {
            exact.put(type, new LinkedHashMap<>());
        }
        grouped.forEach((key, refs) -> {
            int sep = key.indexOf('|');
            IocType type = IocType.valueOf(key.substring(0, sep));
            String value = key.substring(sep + 1);
            refs.sort(Comparator.comparing(SourceRef::sourceId).thenComparingInt(SourceRef::sourceLine));
            SourceRef winner = IocRecord.chooseWinner(refs);
            IocRecord record = new IocRecord(type, value, List.copyOf(refs), winner);
            exact.get(type).put(value, record);
        });
        List<IpCidr> cidrs = new ArrayList<>(exact.get(IocType.CIDR).keySet().stream()
                .map(IpCidr::parseCidr).toList());
        cidrs.addAll(exact.get(IocType.IP).keySet().stream().map(IpCidr::parseCidr).toList());
        return new IntelSnapshot(Instant.now(clock), Map.copyOf(exact), List.copyOf(cidrs),
                Map.copyOf(results), grouped.size());
    }

    private IntelSnapshot emptySnapshot() {
        Map<IocType, Map<String, IocRecord>> exact = new EnumMap<>(IocType.class);
        for (IocType type : IocType.values()) {
            exact.put(type, Map.of());
        }
        return new IntelSnapshot(Instant.now(clock), Map.copyOf(exact), List.of(), Map.of(), 0);
    }
}
