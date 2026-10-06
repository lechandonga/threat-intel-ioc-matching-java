package com.github.lechandonga.threatinteliocmatchingjava.model;

import java.time.Instant;

/**
 * A single indicator claim exactly as contributed by one source, before
 * cross-source conflict resolution.
 *
 * @param source      source id (file name without extension)
 * @param priority    source priority, smaller wins
 * @param row         1-based row in the source file
 * @param type        unified type
 * @param value       normalized value (lower-case hash/domain, canonical IP/CIDR)
 * @param verdict     parsed verdict
 * @param confidence  0..100
 * @param validFrom   inclusive start, defaults to {@link Instant#EPOCH} when absent
 * @param validUntil  exclusive end, defaults to {@link Instant#MAX} when absent
 */
public record RawIndicator(
        String source,
        int priority,
        int row,
        IocType type,
        String value,
        Verdict verdict,
        int confidence,
        Instant validFrom,
        Instant validUntil) {
}
