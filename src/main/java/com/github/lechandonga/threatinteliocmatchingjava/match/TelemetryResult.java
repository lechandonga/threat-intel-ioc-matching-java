package com.github.lechandonga.threatinteliocmatchingjava.match;

import java.time.Instant;
import java.util.List;

/**
 * 单条遥测的匹配结果。{@code rejected} 仅在该遥测记录格式错误时出现，
 * 此时不会再产生告警；错误按记录逐条返回，不影响同批其他记录。
 */
public record TelemetryResult(
        int index,
        String assetId,
        String rawValue,
        MatchStatus status,
        String effectiveVerdict,
        List<Evidence> evidence,
        Instant observedAt,
        String rejectionReason) {

    public static TelemetryResult rejected(int index, String assetId, String rawValue, String reason) {
        return new TelemetryResult(index, assetId, rawValue, null, null,
                List.of(), null, reason);
    }
}
