package com.github.lechandonga.threatinteliocmatchingjava.alert;

import com.github.lechandonga.threatinteliocmatchingjava.config.IntelSourceProperties;
import com.github.lechandonga.threatinteliocmatchingjava.match.Evidence;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 告警生成、抑制与查询。
 *
 * <ul>
 *   <li>抑制键：{@code assetId + "|" + iocType + "|" + iocValue}；</li>
 *   <li>窗口：{@code threat-intel.suppression-window-seconds}（默认 600s），
 *       命中时间落在当前窗口 [windowStart, windowEnd) 内则累计计数，
 *       不产生新告警；窗口结束后再来的命中开新窗口（新告警）；</li>
 *   <li>批次幂等：同一 {@code batchId} 重复投递不会重复计数，也不会
 *       把窗口外的旧批次“复活”；</li>
 *   <li>查询返回不可变快照，与写入并发安全。</li>
 * </ul>
 */
@Service
public class AlertService {

    private static final Logger log = LoggerFactory.getLogger(AlertService.class);

    private final Duration suppressionWindow;
    private final Clock clock;

    /** 抑制键 -> 按窗口起始时间排列的告警序列（保留历史窗口以便查询）。 */
    private final Map<String, ConcurrentSkipListMap<Instant, AlertRecord>> alertsByKey = new ConcurrentHashMap<>();
    /** 已处理过的 (批次, 抑制键) 集合，保证重复投递幂等。 */
    private final Set<String> processedBatchHits = ConcurrentHashMap.newKeySet();
    private final AtomicReference<List<AlertRecord>> cachedView = new AtomicReference<>(List.of());

    public AlertService(IntelSourceProperties properties, Clock clock) {
        this.suppressionWindow = Duration.ofSeconds(properties.getSuppressionWindowSeconds());
        this.clock = clock;
    }

    /**
     * 登记一批生效命中。同一条遥测可因多 IOC 命中产生多个抑制键；
     * 每个键独立抑制。
     */
    public void register(String batchId, String assetId, Instant observedAt, List<Evidence> effectiveEvidence) {
        Map<String, List<Evidence>> byIoc = new LinkedHashMap<>();
        for (Evidence evidence : effectiveEvidence) {
            byIoc.computeIfAbsent(evidence.iocType().name() + "|" + evidence.iocValue(),
                    k -> new ArrayList<>()).add(evidence);
        }
        byIoc.forEach((ioc, evidenceList) ->
                registerOne(batchId, assetId, observedAt, ioc, evidenceList));
    }

    private void registerOne(String batchId, String assetId, Instant observedAt,
                             String ioc, List<Evidence> evidenceList) {
        String dedupToken = (batchId == null ? "" : batchId) + "|" + assetId + "|" + ioc;
        if (batchId != null && !batchId.isBlank() && !processedBatchHits.add(dedupToken)) {
            log.info("duplicate delivery suppressed: batch={} asset={} ioc={}", batchId, assetId, ioc);
            return;
        }

        String key = assetId + "|" + ioc;
        ConcurrentSkipListMap<Instant, AlertRecord> windows =
                alertsByKey.computeIfAbsent(key, k -> new ConcurrentSkipListMap<>());

        synchronized (windows) {
            Map.Entry<Instant, AlertRecord> candidate = windows.floorEntry(observedAt);
            if (candidate != null && observedAt.isBefore(candidate.getValue().windowEnd())) {
                AlertRecord updated = candidate.getValue().withHit(observedAt, batchId, winningEvidence(evidenceList));
                windows.put(candidate.getKey(), updated);
                publishView();
                log.debug("alert suppressed within window: key={} hitCount={}", key, updated.hitCount());
                return;
            }
            Instant windowStart = Instant.ofEpochMilli(
                    Math.floorDiv(observedAt.toEpochMilli(), suppressionWindow.toMillis())
                            * suppressionWindow.toMillis());
            Instant windowEnd = windowStart.plus(suppressionWindow);
            String verdict = evidenceList.stream()
                    .filter(Evidence::conflictWinner)
                    .max(Comparator.comparingInt(e -> e.verdict().rank()))
                    .map(e -> e.verdict().wireName())
                    .orElse(evidenceList.get(0).verdict().wireName());
            int sep = ioc.indexOf('|');
            AlertRecord alert = new AlertRecord(key, assetId, ioc.substring(0, sep),
                    ioc.substring(sep + 1), verdict,
                    observedAt, observedAt, windowStart, windowEnd, 1,
                    batchId == null || batchId.isBlank() ? List.of() : new ArrayList<>(List.of(batchId)),
                    winningEvidence(evidenceList));
            windows.put(windowStart, alert);
            publishView();
            log.info("new alert: key={} verdict={} window=[{} - {})",
                    key, verdict, windowStart, windowEnd);
        }
    }

    private static List<Evidence> winningEvidence(List<Evidence> evidenceList) {
        return evidenceList.stream().filter(Evidence::conflictWinner).toList();
    }

    private void publishView() {
        List<AlertRecord> all = new ArrayList<>();
        alertsByKey.values().forEach(map -> all.addAll(map.values()));
        all.sort(Comparator.comparing(AlertRecord::firstSeen).thenComparing(AlertRecord::alertKey));
        cachedView.set(List.copyOf(all));
    }

    /** 查询当前告警（历史窗口的也保留），返回不可变列表。 */
    public List<AlertRecord> query(String assetId, String iocValue, Boolean openOnly) {
        Instant now = Instant.now(clock);
        return cachedView.get().stream()
                .filter(a -> assetId == null || assetId.isBlank() || assetId.equals(a.assetId()))
                .filter(a -> iocValue == null || iocValue.isBlank() || iocValue.equals(a.iocValue()))
                .filter(a -> openOnly == null || !openOnly || now.isBefore(a.windowEnd()))
                .toList();
    }
}
