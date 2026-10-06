package com.github.lechandonga.threatinteliocmatchingjava.model;

import java.time.Instant;

/**
 * 某条情报在单个来源中的原始记录，是冲突裁决的输入与依据。
 */
public record SourceRef(
        String sourceId,
        long sourcePriority,
        Verdict verdict,
        String severity,
        Instant validFrom,
        Instant validUntil,
        Instant firstSeen,
        String description,
        int sourceLine) {
}
