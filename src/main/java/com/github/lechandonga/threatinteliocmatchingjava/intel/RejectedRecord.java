package com.github.lechandonga.threatinteliocmatchingjava.intel;

/**
 * 被拒绝的单条情报/遥测记录，按行号与原始内容给出可区分的原因。
 */
public record RejectedRecord(
        int line,
        String raw,
        String reason) {
}
