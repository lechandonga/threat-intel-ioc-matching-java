package com.github.lechandonga.threatinteliocmatchingjava.intel;

import com.github.lechandonga.threatinteliocmatchingjava.model.IocRecord;
import com.github.lechandonga.threatinteliocmatchingjava.model.IocType;
import com.github.lechandonga.threatinteliocmatchingjava.net.IpCidr;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * 某一时刻情报库的不可变快照。匹配过程只读快照，
 * 刷新通过整体替换引用来发布，因此查询永远只能看到
 * 刷新前或刷新后的完整状态，不会读到半刷新结果。
 */
public record IntelSnapshot(
        Instant builtAt,
        Map<IocType, Map<String, IocRecord>> exactIndex,
        List<IpCidr> cidrIndex,
        Map<String, SourceLoadResult> sourceResults,
        int recordCount) {

    public IocRecord exact(IocType type, String value) {
        Map<String, IocRecord> byType = exactIndex.get(type);
        return byType == null ? null : byType.get(value);
    }

    /** 命中该 IP 的所有单 IP 与 CIDR 情报（网段边界由 {@link IpCidr#contains} 保证）。 */
    public List<IocRecord> matchIp(long ip) {
        return cidrIndex.stream()
                .filter(c -> c.contains(ip))
                .map(c -> c.cidr()
                        ? exact(IocType.CIDR, c.toString())
                        : exact(IocType.IP, c.toString()))
                .filter(r -> r != null)
                .toList();
    }
}
