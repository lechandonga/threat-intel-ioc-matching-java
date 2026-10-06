package com.github.lechandonga.threatinteliocmatchingjava.model;

/**
 * Unified verdict. Higher {@link #severity()} means a stronger malicious claim,
 * which is used as the second tie-breaker when sources disagree.
 */
public enum Verdict {
    BENIGN(0),
    UNKNOWN(1),
    SUSPICIOUS(2),
    MALICIOUS(3);

    private final int severity;

    Verdict(int severity) {
        this.severity = severity;
    }

    public int severity() {
        return severity;
    }
}
