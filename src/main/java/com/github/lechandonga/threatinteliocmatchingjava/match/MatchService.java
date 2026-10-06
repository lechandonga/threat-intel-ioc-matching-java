package com.github.lechandonga.threatinteliocmatchingjava.match;

import com.github.lechandonga.threatinteliocmatchingjava.alert.AlertService;
import com.github.lechandonga.threatinteliocmatchingjava.intel.IntelSnapshot;
import com.github.lechandonga.threatinteliocmatchingjava.intel.IntelService;
import com.github.lechandonga.threatinteliocmatchingjava.model.IocRecord;
import com.github.lechandonga.threatinteliocmatchingjava.model.IocType;
import com.github.lechandonga.threatinteliocmatchingjava.model.SourceRef;
import com.github.lechandonga.threatinteliocmatchingjava.net.IpCidr;
import com.github.lechandonga.threatinteliocmatchingjava.normalize.Normalize;
import com.github.lechandonga.threatinteliocmatchingjava.normalize.Times;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 遥测匹配服务。匹配期间持有不可变快照引用，与情报刷新天然隔离；
 * 单条遥测命中多条情报时全部展开为 {@link Evidence}。
 */
@Service
public class MatchService {

    private static final Logger log = LoggerFactory.getLogger(MatchService.class);

    private final IntelService intelService;
    private final AlertService alertService;
    private final Clock clock;

    public MatchService(IntelService intelService, AlertService alertService, Clock clock) {
        this.intelService = intelService;
        this.alertService = alertService;
        this.clock = clock;
    }

    public List<TelemetryResult> matchBatch(String batchId, List<TelemetryRequest.Event> events) {
        IntelSnapshot snapshot = intelService.snapshot();
        Instant nowDefault = Instant.now(clock);
        List<TelemetryResult> results = new ArrayList<>();
        if (events == null) {
            return results;
        }
        int index = 0;
        for (TelemetryRequest.Event event : events) {
            results.add(matchOne(snapshot, batchId, index++, event, nowDefault));
        }
        return results;
    }

    private TelemetryResult matchOne(IntelSnapshot snapshot, String batchId, int index,
                                     TelemetryRequest.Event event, Instant nowDefault) {
        String assetId = event == null ? null : event.getAssetId();
        String raw = event == null ? null : event.getValue();
        Instant observedAt;
        try {
            observedAt = event != null && event.getObservedAt() != null
                    ? Times.parse(event.getObservedAt(), "observedAt", index)
                    : nowDefault;
        } catch (IllegalArgumentException e) {
            return TelemetryResult.rejected(index, assetId, raw, e.getMessage());
        }
        if (assetId == null || assetId.isBlank()) {
            return TelemetryResult.rejected(index, assetId, raw, "line " + (index + 1) + ": assetId is required");
        }

        final Normalize.NormValue normalized;
        try {
            normalized = Normalize.detectTelemetry(raw);
        } catch (IllegalArgumentException e) {
            return TelemetryResult.rejected(index, assetId, raw, "line " + (index + 1) + ": " + e.getMessage());
        }

        List<IocRecord> candidates = collectCandidates(snapshot, normalized.type(), normalized.value());
        if (candidates.isEmpty()) {
            return new TelemetryResult(index, assetId, normalized.value(), MatchStatus.NO_MATCH,
                    null, List.of(), observedAt, null);
        }

        List<Evidence> evidence = new ArrayList<>();
        for (IocRecord record : dedup(candidates)) {
            for (SourceRef ref : record.sources()) {
                evidence.add(new Evidence(
                        record.type(), record.value(),
                        matchKind(normalized.type(), record, normalized.value()),
                        ref.sourceId(), ref.sourcePriority(), ref.verdict(), ref.severity(),
                        ref.validFrom(), ref.validUntil(),
                        record.effectiveAt(ref, observedAt),
                        ref.equals(record.winner()),
                        ref.description()));
            }
        }

        List<Evidence> effective = evidence.stream().filter(Evidence::effective).toList();
        MatchStatus status;
        if (!effective.isEmpty()) {
            status = MatchStatus.MATCH;
        } else {
            boolean anyFuture = evidence.stream().anyMatch(e ->
                    e.validFrom() != null && observedAt.isBefore(e.validFrom()));
            status = anyFuture ? MatchStatus.NOT_YET_VALID : MatchStatus.EXPIRED;
        }

        String effectiveVerdict = effective.stream()
                .filter(Evidence::conflictWinner)
                .map(e -> e.verdict().wireName())
                .findFirst()
                .orElse(null);

        if (status == MatchStatus.MATCH) {
            alertService.register(batchId, assetId, observedAt, effective);
        }
        log.debug("telemetry[{}] asset={} value={} -> {} ({} evidence)",
                index, assetId, normalized.value(), status, evidence.size());
        return new TelemetryResult(index, assetId, normalized.value(), status,
                effectiveVerdict, evidence, observedAt, null);
    }

    /**
     * 按语义收集候选情报：
     * 哈希：仅精确值；
     * 域名：精确域 + 祖先域（必须以标签边界 "." 连接，
     * 因此 notevil-example.com 不会命中 evil-example.com）；
     * IP：单 IP + 所有包含该 IP 的 CIDR（边界严格）；
     * CIDR 遥测：仅完全相同的网段情报（子网/超网不算命中，避免范围歧义）。
     */
    private List<IocRecord> collectCandidates(IntelSnapshot snapshot, IocType type, String value) {
        List<IocRecord> out = new ArrayList<>();
        switch (type) {
            case HASH_MD5, HASH_SHA1, HASH_SHA256, IP -> {
                IocRecord exact = snapshot.exact(type, value);
                if (exact != null) {
                    out.add(exact);
                }
                if (type == IocType.IP) {
                    out.addAll(snapshot.matchIp(IpCidr.parseCidr(value).network()));
                }
            }
            case CIDR -> {
                IocRecord exact = snapshot.exact(IocType.CIDR, value);
                if (exact != null) {
                    out.add(exact);
                }
            }
            case DOMAIN -> {
                String current = value;
                while (true) {
                    IocRecord exact = snapshot.exact(IocType.DOMAIN, current);
                    if (exact != null) {
                        out.add(exact);
                    }
                    int dot = current.indexOf('.');
                    if (dot < 0) {
                        break;
                    }
                    current = current.substring(dot + 1);
                }
            }
        }
        return out;
    }

    private static String matchKind(IocType telemetryType, IocRecord record, String telemetryValue) {
        if (telemetryType == IocType.DOMAIN && !record.value().equals(telemetryValue)) {
            return "SUBDOMAIN_OF_INDICATOR_DOMAIN";
        }
        if (telemetryType == IocType.IP && record.type() == IocType.CIDR) {
            return "IP_WITHIN_INDICATOR_CIDR";
        }
        return "EXACT";
    }

    private static List<IocRecord> dedup(List<IocRecord> records) {
        Set<String> seen = new LinkedHashSet<>();
        List<IocRecord> out = new ArrayList<>();
        for (IocRecord record : records) {
            if (seen.add(record.type().name() + "|" + record.value())) {
                out.add(record);
            }
        }
        return out;
    }
}
