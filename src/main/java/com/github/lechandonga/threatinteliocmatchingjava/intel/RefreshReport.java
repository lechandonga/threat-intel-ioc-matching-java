package com.github.lechandonga.threatinteliocmatchingjava.intel;

import java.time.Instant;
import java.util.List;

/**
 * 一次刷新动作的结果报告（HTTP 返回体）。失败源不会清空旧情报，
 * 报告中同时给出本次加载状态与最终生效的快照版本。
 */
public record RefreshReport(
        Instant refreshedAt,
        boolean complete,
        int totalIocCount,
        List<SourceLoadResult> sources) {
}
