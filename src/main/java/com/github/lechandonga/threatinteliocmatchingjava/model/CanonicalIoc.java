package com.github.lechandonga.threatinteliocmatchingjava.model;

import java.time.Instant;
import java.util.List;

/**
 * One normalized IOC after merging every contributing source claim.
 *
 * <p>Conflict resolution is fully deterministic (see {@code ConflictResolver}):
 * the winning claim is the one with smallest source priority, then highest
 * verdict severity, then highest confidence, then latest validUntil, then
 * earliest validFrom, then lexicographically smallest source id. The winner
 * controls verdict/confidence/lifecycle; the winning basis and every claim are
 * retained so the provenance is visible in API results.
 */
public record CanonicalIoc(
        IocType type,
        String value,
        Verdict verdict,
        int confidence,
        Instant validFrom,
        Instant validUntil,
        String winningSource,
        String resolutionBasis,
        List<ClaimView> claims) {

    /**
     * One contributing claim with its source and lifecycle state.
     */
    public record ClaimView(
            String source,
            int priority,
            Verdict verdict,
            int confidence,
            Instant validFrom,
            Instant validUntil,
            LifecycleState state) {
    }
}
