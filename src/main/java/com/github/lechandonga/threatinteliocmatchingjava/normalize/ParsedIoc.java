package com.github.lechandonga.threatinteliocmatchingjava.normalize;

/**
 * 解析器产出的原始字段（尚未做值校验与类型映射），
 * 行号用于逐条拒绝信息的定位。
 */
public record ParsedIoc(
        int line,
        String rawType,
        String rawValue,
        String verdict,
        String severity,
        String validFrom,
        String validUntil,
        String firstSeen,
        String description,
        String rawLine) {
}
