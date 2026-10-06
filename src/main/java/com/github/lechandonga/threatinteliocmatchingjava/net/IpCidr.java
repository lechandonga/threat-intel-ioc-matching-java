package com.github.lechandonga.threatinteliocmatchingjava.net;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * IPv4 / CIDR 值对象，匹配时严格按网络位与网段边界处理。
 */
public record IpCidr(long network, int prefix, boolean cidr) {

    public boolean contains(long ip) {
        if (!cidr) {
            return network == ip;
        }
        if (prefix == 0) {
            return true;
        }
        long mask = prefix == 32 ? 0xFFFFFFFFL : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        return (ip & mask) == (network & mask);
    }

    public static long parseIp(String raw) {
        String value = raw == null ? "" : raw.trim();
        InetAddress addr;
        try {
            addr = InetAddress.getByName(value);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("invalid IPv4: " + raw);
        }
        if (!(addr instanceof Inet4Address) || !addr.getHostAddress().equals(value)) {
            throw new IllegalArgumentException("invalid IPv4 (non-IPv4 or resolved hostname): " + raw);
        }
        long ip = 0;
        for (byte octet : addr.getAddress()) {
            ip = (ip << 8) | (octet & 0xFF);
        }
        return ip;
    }

    /**
     * 解析 CIDR，要求是规范网络地址（主机位必须为 0），
     * 避免 {@code 10.0.0.5/24} 这类有歧义的写法悄悄被接受。
     */
    public static IpCidr parseCidr(String raw) {
        String value = raw == null ? "" : raw.trim();
        int slash = value.indexOf('/');
        if (slash < 0) {
            return new IpCidr(parseIp(value), 32, false);
        }
        long network = parseIp(value.substring(0, slash));
        int prefix;
        try {
            prefix = Integer.parseInt(value.substring(slash + 1).trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("invalid CIDR prefix: " + raw);
        }
        if (prefix < 0 || prefix > 32) {
            throw new IllegalArgumentException("CIDR prefix out of range 0-32: " + raw);
        }
        long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        if ((network & ~mask) != 0) {
            throw new IllegalArgumentException(
                    "non-canonical CIDR (host bits must be zero), use " + format(network & mask, prefix) + ": " + raw);
        }
        return new IpCidr(network, prefix, prefix < 32);
    }

    private static String format(long network, int prefix) {
        return ((network >> 24) & 0xFF) + "." + ((network >> 16) & 0xFF) + "."
                + ((network >> 8) & 0xFF) + "." + (network & 0xFF) + "/" + prefix;
    }

    @Override
    public String toString() {
        return cidr ? format(network, prefix)
                : ((network >> 24) & 0xFF) + "." + ((network >> 16) & 0xFF) + "."
                        + ((network >> 8) & 0xFF) + "." + (network & 0xFF);
    }
}
