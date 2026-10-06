package com.github.lechandonga.threatinteliocmatchingjava.intel;

import com.github.lechandonga.threatinteliocmatchingjava.model.Verdict;

/**
 * verdict 缺失时给出明确的逐行拒绝原因，而不是默认值。
 */
final class VerdictParser {

    private VerdictParser() {
    }

    static Verdict parse(String raw, int line) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("line " + line + ": verdict is required");
        }
        try {
            return Verdict.parse(raw);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("line " + line + ": " + e.getMessage());
        }
    }
}
