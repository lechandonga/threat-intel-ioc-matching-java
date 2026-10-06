package com.github.lechandonga/threatinteliocmatchingjava.normalize;

/**
 * Parsed IPv4/IPv6 address or CIDR block with boundary-safe containment.
 *
 * <p>A CIDR is only accepted when the host bits are zero (e.g.
 * {@code 10.0.0.0/24} is valid, {@code 10.0.0.1/24} is rejected) so that the
 * block's meaning can never be ambiguous.
 */
public final class IpCidr {

    private final byte[] address;
    private final int prefixLength; // null-less primitive: -1 for a plain address
    private final boolean v6;

    private IpCidr(byte[] address, int prefixLength, boolean v6) {
        this.address = address;
        this.prefixLength = prefixLength;
        this.v6 = v6;
    }

    public boolean isCidr() {
        return prefixLength >= 0;
    }

    /**
     * Canonical text: compressed IP for v6, plain IPv4; CIDR keeps "/prefix".
     */
    public String canonical() {
        String ip = v6 ? compressV6(address) : formatV4(address);
        return isCidr() ? ip + "/" + prefixLength : ip;
    }

    /**
     * Bit length of the address family.
     */
    public int bits() {
        return v6 ? 128 : 32;
    }

    /**
     * True when this block (or exact address) contains the given address.
     */
    public boolean contains(IpCidr other) {
        if (this.v6 != other.v6) {
            return false;
        }
        if (!isCidr()) {
            return Arrays.equals(address, other.address);
        }
        int common = prefixLength;
        int fullBytes = common / 8;
        for (int i = 0; i < fullBytes; i++) {
            if (address[i] != other.address[i]) {
                return false;
            }
        }
        int rem = common % 8;
        if (rem != 0) {
            int mask = 0xFF << (8 - rem);
            if ((address[fullBytes] & mask) != (other.address[fullBytes] & mask)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Network address after masking host bits.
     */
    private static byte[] networkOf(byte[] addr, int prefix) {
        byte[] net = addr.clone();
        int bits = addr.length * 8;
        for (int i = prefix; i < bits; i++) {
            net[i / 8] &= (byte) ~(1 << (7 - (i % 8)));
        }
        return net;
    }

    private static String formatV4(byte[] a) {
        return (a[0] & 0xFF) + "." + (a[1] & 0xFF) + "." + (a[2] & 0xFF) + "." + (a[3] & 0xFF);
    }

    private static String compressV6(byte[] a) {
        int[] words = new int[8];
        for (int i = 0; i < 8; i++) {
            words[i] = ((a[2 * i] & 0xFF) << 8) | (a[2 * i + 1] & 0xFF);
        }
        int bestStart = -1;
        int bestLen = 0;
        int runStart = -1;
        for (int i = 0; i <= 8; i++) {
            if (i < 8 && words[i] == 0) {
                if (runStart < 0) {
                    runStart = i;
                }
            } else if (runStart >= 0) {
                int len = i - runStart;
                if (len >= 2 && len > bestLen) {
                    bestStart = runStart;
                    bestLen = len;
                }
                runStart = -1;
            }
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i == bestStart) {
                sb.append(i == 0 ? "::" : ":");
                i += bestLen - 1;
                continue;
            }
            sb.append(Integer.toHexString(words[i]));
            if (i < 7) {
                sb.append(':');
            }
        }
        return sb.toString();
    }

    /**
     * Parse an IP address or CIDR. Returns null when invalid.
     *
     * @param rejectHostBits if true and the token is a CIDR with non-zero host
     *                       bits, parsing fails for that specific reason
     */
    public static ParseOutcome parse(String token, boolean rejectHostBits) {
        String t = token.trim();
        int slash = t.indexOf('/');
        try {
            if (slash < 0) {
                byte[] addr = parseIp(t);
                return new ParseOutcome(new IpCidr(addr, -1, addr.length == 16), null);
            }
            String ipPart = t.substring(0, slash);
            String prefixPart = t.substring(slash + 1);
            if (prefixPart.indexOf('/') >= 0 || prefixPart.isBlank()) {
                return ParseOutcome.invalid("malformed CIDR: " + token);
            }
            int prefix = Integer.parseInt(prefixPart.trim());
            byte[] addr = parseIp(ipPart);
            int max = addr.length * 8;
            if (prefix < 0 || prefix > max) {
                return ParseOutcome.invalid("CIDR prefix out of range: " + token);
            }
            byte[] net = networkOf(addr, prefix);
            if (rejectHostBits && !java.util.Arrays.equals(net, addr)) {
                return new ParseOutcome(null, new ValueFailure(
                        com.github.lechandonga.threatinteliocmatchingjava.model.RejectReason.CIDR_HAS_HOST_BITS,
                        "CIDR has non-zero host bits, use " + canonicalOf(net, prefix) + ": " + token));
            }
            return new ParseOutcome(new IpCidr(net, prefix, addr.length == 16), null);
        } catch (IllegalArgumentException e) {
            return ParseOutcome.invalid(e.getMessage());
        }
    }

    private static String canonicalOf(byte[] net, int prefix) {
        IpCidr c = new IpCidr(net, prefix, net.length == 16);
        return c.canonical();
    }

    private static byte[] parseIp(String s) {
        if (s.indexOf(':') >= 0) {
            return parseV6(s.trim());
        }
        return parseV4(s.trim());
    }

    private static byte[] parseV4(String s) {
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) {
            throw new IllegalArgumentException("not an IPv4 address: " + s);
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            String p = parts[i];
            if (p.isEmpty() || p.length() > 3 || !p.chars().allMatch(Character::isDigit)) {
                throw new IllegalArgumentException("not an IPv4 address: " + s);
            }
            if (p.length() > 1 && p.charAt(0) == '0') {
                throw new IllegalArgumentException("leading zeros are not allowed: " + s);
            }
            int n = Integer.parseInt(p);
            if (n > 255) {
                throw new IllegalArgumentException("octet out of range: " + s);
            }
            out[i] = (byte) n;
        }
        return out;
    }

    private static byte[] parseV6(String s) {
        // Disallow embedded IPv4 for strictness; require colon hex form.
        if (s.indexOf('.') >= 0) {
            throw new IllegalArgumentException("embedded IPv4 not supported: " + s);
        }
        int dc = s.indexOf("::");
        String head = dc < 0 ? s : s.substring(0, dc);
        String tail = dc < 0 ? "" : s.substring(dc + 2);
        if (dc >= 0 && (tail.contains("::") || head.contains("::"))) {
            throw new IllegalArgumentException("multiple :: in: " + s);
        }
        String[] headParts = head.isEmpty() ? new String[0] : head.split(":", -1);
        String[] tailParts = tail.isEmpty() ? new String[0] : tail.split(":", -1);
        for (String p : headParts) {
            checkHexGroup(p, s);
        }
        for (String p : tailParts) {
            checkHexGroup(p, s);
        }
        int specified = headParts.length + tailParts.length;
        if (dc < 0 && specified != 8) {
            throw new IllegalArgumentException("IPv6 must have 8 groups: " + s);
        }
        if (dc >= 0 && specified > 7) {
            throw new IllegalArgumentException("too many groups in: " + s);
        }
        int[] words = new int[8];
        int idx = 0;
        for (String p : headParts) {
            words[idx++] = Integer.parseInt(p, 16);
        }
        idx = 8;
        for (int i = tailParts.length - 1; i >= 0; i--) {
            words[--idx] = Integer.parseInt(tailParts[i], 16);
        }
        byte[] out = new byte[16];
        for (int i = 0; i < 8; i++) {
            out[2 * i] = (byte) (words[i] >> 8);
            out[2 * i + 1] = (byte) words[i];
        }
        return out;
    }

    private static void checkHexGroup(String p, String full) {
        if (p.isEmpty() || p.length() > 4 || !p.chars().allMatch(ValueValidatorsHolder::isHex)) {
            throw new IllegalArgumentException("not an IPv6 address: " + full);
        }
    }

    private static final class ValueValidatorsHolder {
        static boolean isHex(int c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        }
    }

    /**
     * Parse outcome for callers that need to distinguish host-bit rejection.
     */
    public record ParseOutcome(IpCidr value, ValueFailure failure) {
        static ParseOutcome invalid(String detail) {
            return new ParseOutcome(null,
                    new ValueFailure(com.github.lechandonga.threatinteliocmatchingjava.model.RejectReason.INVALID_IP_OR_CIDR, detail));
        }
    }

    /**
     * Typed failure carrying a stable reason.
     */
    public record ValueFailure(com.github.lechandonga.threatinteliocmatchingjava.model.RejectReason reason, String detail) {
    }
}
