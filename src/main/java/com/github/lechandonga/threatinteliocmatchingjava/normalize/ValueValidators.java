package com.github.lechandonga.threatinteliocmatchingjava.normalize;

import com.github.lechandonga.threatinteliocmatchingjava.model.IocType;
import com.github.lechandonga.threatinteliocmatchingjava.model.RejectReason;

/**
 * Result of parsing/normalizing one raw IOC value.
 */
public record ParsedValue(IocType type, String value) {

    /**
     * Parse a raw value whose IOC type is already known (from a typed column).
     */
    public record Failure(RejectReason reason, String detail) {
    }
}
