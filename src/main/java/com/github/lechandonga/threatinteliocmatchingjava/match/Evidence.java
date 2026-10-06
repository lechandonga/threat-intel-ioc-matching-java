package com.github.lechandonga.threatinteliocmatchingjava.match;

import com.github.lechandonga.threatinteliocmatchingjava.model.IocType;
import com.github.lechandonga.threatinteliocmatchingjava.model.Verdict;

import java.time.Instant;

/**
 * 一条命中依据：完整暴露 IOC 身份、来源、判定、有效期与
 * “是否被冲突裁决选中”，单条遥测命中多条情报时逐条返回。
 */
public record Evidence(
        IocType iocType,
        String iocValue,
        String matchKind,
        String sourceId,
        long sourcePriority,
        Verdict verdict,
        String severity,
        Instant validFrom,
        Instant validUntil,
        boolean effective,
        boolean conflictWinner,
        String description) {
}
