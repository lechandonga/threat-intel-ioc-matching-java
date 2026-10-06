package com.github.lechandonga.threatinteliocmatchingjava.normalize;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.threatinteliocmatchingjava.config.IntelSourceProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 简易 JSON 情报源：
 * <pre>{@code
 * { "indicators": [
 *   {"type":"sha256|sha1|md5|domain|ip|cidr", "value":"...",
 *    "verdict":"malicious|suspicious|clean", "severity":"high",
 *    "validFrom":"2026-01-01T00:00:00Z", "validUntil":"...",
 *    "firstSeen":"...", "description":"..."}
 * ]}
 * }</pre>
 * 时间字段接受 ISO-8601 或 epoch 毫秒。
 */
@Component
public class JsonFeedParser implements IntelSourceParser {

    private final ObjectMapper mapper;

    public JsonFeedParser(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public IntelSourceProperties.Format format() {
        return IntelSourceProperties.Format.JSON_FEED;
    }

    @Override
    public List<ParsedIoc> parse(Path file) throws IOException {
        JsonNode root = mapper.readTree(IntelSourceParser.readString(file));
        if (root == null || !root.isObject() || root.get("indicators") == null || !root.get("indicators").isArray()) {
            throw new IOException("json-feed requires an object with an 'indicators' array");
        }
        List<ParsedIoc> out = new ArrayList<>();
        int line = 0;
        for (JsonNode node : root.get("indicators")) {
            line++;
            out.add(new ParsedIoc(line,
                    text(node, "type"), text(node, "value"), text(node, "verdict"),
                    text(node, "severity"), text(node, "validFrom"), text(node, "validUntil"),
                    text(node, "firstSeen"), text(node, "description"), node.toString()));
        }
        return out;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        if (value.isNumber()) {
            return value.asText();
        }
        return value.asText();
    }
}
