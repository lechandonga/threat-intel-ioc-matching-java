package com.github.lechandonga.threatinteliocmatchingjava.model;

/**
 * 情报判定。同一 IOC 被多个来源给出不同判定时，按
 * {@code rank} 从大到小排序取最高等级（恶意 &gt; 可疑 &gt; 白名单）。
 */
public enum Verdict {
    CLEAN(0, "clean"),
    SUSPICIOUS(1, "suspicious"),
    MALICIOUS(2, "malicious");

    private final int rank;
    private final String wireName;

    Verdict(int rank, String wireName) {
        this.rank = rank;
        this.wireName = wireName;
    }

    public int rank() {
        return rank;
    }

    public String wireName() {
        return wireName;
    }

    /**
     * 解析各情报源里的判定写法，大小写与空格不敏感。
     *
     * @throws IllegalArgumentException 无法识别的判定值
     */
    public static Verdict parse(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("verdict is empty");
        }
        String value = raw.trim().toLowerCase().replace('-', '_').replace(' ', '_');
        return switch (value) {
            case "malicious", "malware", "threat", "bad", "blacklist", "block", "2" -> MALICIOUS;
            case "suspicious", "suspect", "grey", "gray", "watch", "1" -> SUSPICIOUS;
            case "clean", "benign", "whitelist", "allow", "0" -> CLEAN;
            default -> throw new IllegalArgumentException("unknown verdict: " + raw);
        };
    }
}
