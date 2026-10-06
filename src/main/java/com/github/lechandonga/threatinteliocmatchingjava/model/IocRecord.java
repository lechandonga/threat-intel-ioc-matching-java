package com.github.lechandonga.threatinteliocmatchingjava.model;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;

/**
 * 归一后的 IOC。{@code value} 为规范化后的匹配值（域名小写、哈希小写、
 * CIDR 网络地址），所有来源对该 IOC 的原始判定都保留在 {@code sources} 中，
 * {@code winner} 记录冲突裁决结果及其依据，保证可复现、可追溯。
 */
public record IocRecord(
        IocType type,
        String value,
        List<SourceRef> sources,
        SourceRef winner) {

    /**
     * 冲突裁决规则（确定且可复现）：
     * <ol>
     *   <li>判定等级高者胜：MALICIOUS &gt; SUSPICIOUS &gt; CLEAN；</li>
     *   <li>同等级时来源优先级数值大者胜（配置中 priority 越高越权威）；</li>
     *   <li>仍相同时，firstSeen 更早者胜；</li>
     *   <li>仍相同时，sourceId 字典序靠前者胜。</li>
     * </ol>
     */
    public static SourceRef chooseWinner(List<SourceRef> refs) {
        Comparator<SourceRef> earlierFirstSeen =
                Comparator.comparing(r -> r.firstSeen() == null ? Instant.MAX : r.firstSeen());
        Comparator<SourceRef> smallerSourceId =
                Comparator.comparing(r -> r.sourceId() == null ? "" : r.sourceId());
        return refs.stream().min(
                        Comparator.comparingInt((SourceRef r) -> -r.verdict().rank())
                                .thenComparing(r -> -r.sourcePriority())
                                .thenComparing(earlierFirstSeen)
                                .thenComparing(smallerSourceId))
                .orElseThrow();
    }

    /**
     * 有效期是否覆盖给定时刻（半开区间 [validFrom, validUntil)）。
     * 空边界表示无限制。
     */
    public boolean effectiveAt(SourceRef ref, Instant now) {
        if (ref.validFrom() != null && now.isBefore(ref.validFrom())) {
            return false;
        }
        return ref.validUntil() == null || now.isBefore(ref.validUntil());
    }
}
