package com.github.lechandonga.threatinteliocmatchingjava.alert;

import com.github.lechandonga.threatinteliocmatchingjava.match.Evidence;

import java.time.Instant;
import java.util.List;

/**
 * 告警。抑制键 = assetId + IOC 身份（type|value）；窗口内重复命中
 * 只更新同一告警：累计 {@code hitCount}，扩展时间范围与批次集合。
 */
public record AlertRecord(
        String alertKey,
        String assetId,
        String iocType,
        String iocValue,
        String verdict,
        Instant firstSeen,
        Instant lastSeen,
        Instant windowStart,
        Instant windowEnd,
        long hitCount,
        List<String> batchIds,
        List<Evidence> winningEvidence) {

    AlertRecord withHit(Instant observedAt, String batchId, List<Evidence> evidence) {
        List<String> batches = new java.util.ArrayList<>(batchIds);
        if (batchId != null && !batchId.isBlank() && !batches.contains(batchId)) {
            batches.add(batchId);
        }
        return new AlertRecord(alertKey, assetId, iocType, iocValue, verdict,
                firstSeen, observedAt.isAfter(lastSeen) ? observedAt : lastSeen,
                windowStart, windowEnd, hitCount + 1,
                List.copyOf(batches), evidence);
    }
}
