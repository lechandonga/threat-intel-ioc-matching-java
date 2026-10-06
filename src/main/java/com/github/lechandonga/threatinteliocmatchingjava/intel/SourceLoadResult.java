package com.github.lechandonga.threatinteliocmatchingjava.intel;

import java.util.List;

/**
 * 单个情报源的加载结果。整体失败（IO 异常、格式不支持等）与
 * “部分记录被拒绝”严格区分：前者 {@code fatalError} 非空且
 * {@code accepted} 为空，调用方必须保留该源的旧数据。
 */
public record SourceLoadResult(
        String sourceId,
        boolean success,
        String fatalError,
        int accepted,
        List<RejectedRecord> rejected) {

    public static SourceLoadResult loaded(String sourceId, int accepted, List<RejectedRecord> rejected) {
        return new SourceLoadResult(sourceId, true, null, accepted, List.copyOf(rejected));
    }

    public static SourceLoadResult failed(String sourceId, String fatalError) {
        return new SourceLoadResult(sourceId, false, fatalError, 0, List.of());
    }
}
