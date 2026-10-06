package com.github.lechandonga.threatinteliocmatchingjava.normalize;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.threatinteliocmatchingjava.config.IntelSourceProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * STIX 2.1 Bundle 子集解析器（本地文件，无 TAXII 依赖）：
 * <pre>{@code
 * {"type":"bundle","objects":[
 *   {"type":"indicator",
 *    "pattern":"[file:hashes.'SHA-256' = 'abc...']",
 *    "labels":["malicious-activity"],
 *    "valid_from":"...", "valid_until":"...", "created":"...",
 *    "name":"..."}
 * ]}
 * }</pre>
 * 支持的 pattern 形式：
 * <ul>
 *   <li>{@code [file:hashes.'SHA-256' = '...']}（SHA-256/SHA-1/MD5）</li>
 *   <li>{@code [domain-name:value = 'example.com']}</li>
 *   <li>{@code [ipv4-addr:value = '10.0.0.0/8']}（单 IP 或 CIDR）</li>
 * </ul>
 * 判定从 labels / indicator_types 推断：malicious-activity→malicious，
 * suspicious-activity/anomaly→suspicious，benign→clean；缺省 malicious。
 */
@Component
public class StixBundleParser implements IntelSourceParser {

    private static final Pattern FILE_HASH = Pattern.compile(
            "file:hashes\\.'?(SHA-?256|SHA-?1|MD5)'?\\s*=\\s*'([^']+)'", Pattern.CASE_INSENSITIVE);
    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
            "domain-name:value\\s*=\\s*'([^']+)'", Pattern.CASE_INSENSITIVE);
    private static final Pattern IP_PATTERN = Pattern.compile(
            "ipv4-addr:value\\s*=\\s*'([^']+)'", Pattern.CASE_INSENSITIVE);

    private final ObjectMapper mapper;

    public StixBundleParser(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public IntelSourceProperties.Format format() {
        return IntelSourceProperties.Format.STIX_BUNDLE;
    }

    @Override
    public List<ParsedIoc> parse(Path file) throws IOException {
        JsonNode root = mapper.readTree(IntelSourceParser.readString(file));
        if (root == null || !"bundle".equals(text(root.get("type")))
                || root.get("objects") == null || !root.get("objects").isArray()) {
            throw new IOException("stix bundle requires {\"type\":\"bundle\",\"objects\":[...]}");
        }
        List<ParsedIoc> out = new ArrayList<>();
        int line = 0;
        for (JsonNode obj : root.get("objects")) {
            line++;
            if (!"indicator".equals(text(obj.get("type")))) {
                continue;
            }
            String pattern = text(obj.get("pattern"));
            String rawType = null;
            String rawValue = null;
            if (pattern != null) {
                Matcher hash = FILE_HASH.matcher(pattern);
                Matcher domain = DOMAIN_PATTERN.matcher(pattern);
                Matcher ip = IP_PATTERN.matcher(pattern);
                if (hash.find()) {
                    rawType = hash.group(1).toUpperCase().replace("-", "");
                    rawValue = hash.group(2);
                } else if (domain.find()) {
                    rawType = "domain";
                    rawValue = domain.group(1);
                } else if (ip.find()) {
                    rawType = ip.group(1).contains("/") ? "cidr" : "ip";
                    rawValue = ip.group(1);
                }
            }
            String verdict = stixVerdict(obj);
            out.add(new ParsedIoc(line, rawType, rawValue, verdict, null,
                    text(obj.get("valid_from")), text(obj.get("valid_until")),
                    text(obj.get("created")), text(obj.get("name")), pattern));
        }
        return out;
    }

    private static String stixVerdict(JsonNode indicator) {
        String labelConcat = "";
        JsonNode labels = indicator.get("labels");
        if (labels != null && labels.isArray()) {
            StringBuilder sb = new StringBuilder();
            labels.forEach(n -> sb.append(n.asText()).append(' '));
            labelConcat = sb.toString().toLowerCase();
        }
        JsonNode types = indicator.get("indicator_types");
        if (types != null && types.isArray()) {
            StringBuilder sb = new StringBuilder(labelConcat);
            types.forEach(n -> sb.append(n.asText()).append(' '));
            labelConcat = sb.toString().toLowerCase();
        }
        if (labelConcat.contains("benign")) {
            return "clean";
        }
        if (labelConcat.contains("suspicious") || labelConcat.contains("anomal")) {
            return "suspicious";
        }
        return "malicious";
    }

    private static String text(JsonNode node) {
        return node == null || node.isNull() ? null : node.asText();
    }
}
