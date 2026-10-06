package com.github.lechandonga.threatinteliocmatchingjava.model;

/**
 * Per-record rejection reasons for malformed feed indicators and telemetry events.
 * Each reason is stable so callers can distinguish records programmatically.
 */
public enum RejectReason {
    BLANK_VALUE,
    UNSUPPORTED_TYPE,
    INVALID_HASH,
    HASH_LENGTH_UNKNOWN_TYPE,
    INVALID_DOMAIN,
    INVALID_IP_OR_CIDR,
    CIDR_HAS_HOST_BITS,
    INVALID_VERDICT,
    INVALID_TIMESTAMP,
    INVALID_TIMESTAMP_RANGE,
    UNPARSEABLE_RECORD,
    MISSING_BATCH_ID,
    DUPLICATE_EVENT_WITHIN_BATCH
}
