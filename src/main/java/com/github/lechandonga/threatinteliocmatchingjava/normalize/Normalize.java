package com.github.lechandonga.threatinteliocmatchingjava.normalize;

import com.github.lechandonga.threatinteliocmatchingjava.model.IocType;
import com.github.lechandonga.threatinteliocmatchingjava.net.IpCidr;

import java.util.regex.Pattern;

/**
 * 各类型 IOC / 遥测值的规范化与校验。校验规则刻意严格，
 * 拒绝所有可能造成歧义匹配的写法。
 */
public final class Normalize {

    private static final Pattern MD5 = Pattern.compile("[0-9a-f]{32}");
    private static final Pattern SHA1 = Pattern.compile("[0-9a-f]{40}");
    private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern DOMAIN_LABEL =
            Pattern.compile("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?");

    private Normalize() {
    }

    public record NormValue(IocType type, String value) {
    }

    /** 按显式类型规范化情报值。 */
    public static NormValue normalize(IocType type, String raw) {
        String value = raw == null ? "" : raw.trim();
        return switch (type) {
            case HASH_MD5, HASH_SHA1, HASH_SHA256 -> new NormValue(type, hash(value, type));
            case DOMAIN -> new NormValue(IocType.DOMAIN, domain(value));
            case IP -> new NormValue(IocType.IP, IpCidr.parseCidr(value).toString());
            case CIDR -> {
                IpCidr cidr = IpCidr.parseCidr(value);
                if (!cidr.cidr()) {
                    throw new IllegalArgumentException("CIDR indicator must contain a prefix (<32), got bare IP: " + raw);
                }
                yield new NormValue(IocType.CIDR, cidr.toString());
            }
        };
    }

    /**
     * 遥测值自动识别类型：带斜杠为 CIDR（遥测允许网段，例如 Netflow 聚合），
     * 点分四段为 IPv4，十六进制长度为哈希，其余按域名。
     */
    public static NormValue detectTelemetry(String raw) {
        String value = raw == null ? "" : raw.trim();
        if (value.isEmpty()) {
            throw new IllegalArgumentException("telemetry value is empty");
        }
        if (value.contains("/")) {
            IpCidr cidr = IpCidr.parseCidr(value);
            return new NormValue(cidr.cidr() ? IocType.CIDR : IocType.IP, cidr.toString());
        }
        if (value.chars().allMatch(c -> (c >= '0' && c <= '9') || c == '.' || c == ':')) {
            return new NormValue(IocType.IP, IpCidr.parseCidr(value).toString());
        }
        String lower = value.toLowerCase();
        if (lower.matches("[0-9a-f]+")) {
            IocType type = switch (lower.length()) {
                case 32 -> IocType.HASH_MD5;
                case 40 -> IocType.HASH_SHA1;
                case 64 -> IocType.HASH_SHA256;
                default -> throw new IllegalArgumentException(
                        "hex value length " + lower.length() + " is not md5(32)/sha1(40)/sha256(64): " + raw);
            };
            return new NormValue(type, lower);
        }
        return new NormValue(IocType.DOMAIN, domain(value));
    }

    private static String hash(String value, IocType expected) {
        String lower = value.toLowerCase();
        Pattern pattern = switch (expected) {
            case HASH_MD5 -> MD5;
            case HASH_SHA1 -> SHA1;
            case HASH_SHA256 -> SHA256;
            default -> throw new IllegalStateException();
        };
        if (!pattern.matcher(lower).matches()) {
            throw new IllegalArgumentException(expected + " must be "
                    + switch (expected) {
                        case HASH_MD5 -> "32";
                        case HASH_SHA1 -> "40";
                        default -> "64";
                    } + " lowercase/uppercase hex chars: " + value);
        }
        return lower;
    }

    private static String domain(String raw) {
        String value = raw.toLowerCase();
        if (value.endsWith(".")) {
            value = value.substring(0, value.length() - 1);
        }
        if (value.isEmpty() || value.contains("..") || value.length() > 253 || value.startsWith("-")) {
            throw new IllegalArgumentException("invalid domain: " + raw);
        }
        String[] labels = value.split("\\.", -1);
        if (labels.length < 2) {
            throw new IllegalArgumentException("domain must contain at least one dot and a TLD: " + raw);
        }
        for (String label : labels) {
            if (!DOMAIN_LABEL.matcher(label).matches() || label.endsWith("-")) {
                throw new IllegalArgumentException("invalid domain label '" + label + "' in: " + raw);
            }
        }
        String tld = labels[labels.length - 1];
        if (!tld.matches("[a-z]{2,63}")) {
            throw new IllegalArgumentException("TLD must be 2-63 ASCII letters: " + raw);
        }
        return value;
    }
}
