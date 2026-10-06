package com.github.lechandonga.threatinteliocmatchingjava.model;

/**
 * IOC 类型，决定匹配语义。
 */
public enum IocType {
    /** SHA-256（64 位十六进制），精确匹配。 */
    HASH_SHA256,
    /** SHA-1（40 位十六进制），精确匹配。 */
    HASH_SHA1,
    /** MD5（32 位十六进制），精确匹配。 */
    HASH_MD5,
    /** 域名，支持子域命中，相似域名必须隔离。 */
    DOMAIN,
    /** 单个 IPv4，精确匹配。 */
    IP,
    /** IPv4 CIDR 网段，按网络/广播边界匹配。 */
    CIDR
}
