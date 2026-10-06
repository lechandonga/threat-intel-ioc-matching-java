package com.github.lechandonga.threatinteliocmatchingjava.match;

/**
 * 单条遥测的匹配状态。过期 / 未生效与“情报不存在”严格区分：
 * <ul>
 *   <li>{@link #MATCH} 存在当前生效的情报；</li>
 *   <li>{@link #EXPIRED} 情报存在但所有来源记录均已过期；</li>
 *   <li>{@link #NOT_YET_VALID} 情报存在但均尚未生效；</li>
 *   <li>{@link #NO_MATCH} 情报库中不存在该 IOC（同未上报）。</li>
 * </ul>
 */
public enum MatchStatus {
    MATCH,
    EXPIRED,
    NOT_YET_VALID,
    NO_MATCH
}
