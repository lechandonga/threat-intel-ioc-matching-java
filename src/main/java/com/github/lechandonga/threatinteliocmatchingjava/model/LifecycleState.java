package com.github.lechandonga.threatinteliocmatchingjava.model;

/**
 * Validity state of an IOC claim at a given instant.
 *
 * <ul>
 *     <li>{@link #ACTIVE} - valid_from &lt;= now &lt; valid_until</li>
 *     <li>{@link #EXPIRED} - now &gt;= valid_until (boundary inclusive, half-open interval)</li>
 *     <li>{@link #PENDING} - now &lt; valid_from</li>
 * </ul>
 *
 * <p>Time interval is half-open: an IOC is active for [valid_from, valid_until).
 * This makes boundary conditions deterministic and easy to reproduce.
 */
public enum LifecycleState {
    ACTIVE,
    PENDING,
    EXPIRED
}
