package com.github.lechandonga.threatinteliocmatchingjava.normalize;

import java.time.Instant;
import java.time.format.DateTimeParseException;

/**
 * 时间解析：ISO-8601（如 {@code 2026-10-01T00:00:00Z}）或 epoch 毫秒；
 * 空串视为无边界。
 */
public final class Times {

    private Times() {
    }

    public static Instant parse(String raw, String field, int line) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String value = raw.trim();
        try {
            if (value.matches("-?\\d{10,13}")) {
                long millis = Long.parseLong(value);
                if (value.length() == 10) {
                    millis *= 1000;
                }
                return Instant.ofEpochMilli(millis);
            }
            return Instant.parse(value);
        } catch (DateTimeParseException | NumberFormatException e) {
            throw new IllegalArgumentException(
                    "line " + line + ": invalid " + field + " '" + raw + "' (use ISO-8601 or epoch millis)");
        }
    }
}
