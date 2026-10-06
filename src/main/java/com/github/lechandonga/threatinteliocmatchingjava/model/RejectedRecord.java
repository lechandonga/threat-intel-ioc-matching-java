package com.github.lechandonga.threatinteliocmatchingjava.model;

/**
 * One rejected feed indicator or telemetry event, with the reason and enough
 * location information to explain why the whole batch is still usable.
 *
 * @param source   feed source (null for telemetry)
 * @param row      1-based row/record number inside the source file or batch
 * @param rawValue raw value that failed validation, best effort
 * @param reason   stable rejection reason
 * @param detail   human readable detail
 */
public record RejectedRecord(
        String source,
        Integer row,
        String rawValue,
        RejectReason reason,
        String detail) {
}
