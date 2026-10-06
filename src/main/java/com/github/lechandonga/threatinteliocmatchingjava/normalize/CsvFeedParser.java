package com.github.lechandonga.threatinteliocmatchingjava.normalize;

import com.github.lechandonga.threatinteliocmatchingjava.config.IntelSourceProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 管道分隔的 CSV 情报源（无第三方依赖，引号转义使用 {@code |} 之外的简单规则）：
 * <pre>
 * # 注释行
 * type|value|verdict|severity|validFrom|validUntil|firstSeen|description
 * </pre>
 * 首行为表头；时间字段接受 ISO-8601 或 epoch 毫秒，空值表示无边界。
 */
@Component
public class CsvFeedParser implements IntelSourceParser {

    @Override
    public IntelSourceProperties.Format format() {
        return IntelSourceProperties.Format.CSV;
    }

    @Override
    public List<ParsedIoc> parse(Path file) throws IOException {
        List<String> lines = IntelSourceParser.readString(file).lines().toList();
        if (lines.isEmpty()) {
            throw new IOException("csv file is empty, header line required");
        }
        List<ParsedIoc> out = new ArrayList<>();
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (i == 0 || line.isBlank() || line.stripLeading().startsWith("#")) {
                continue;
            }
            String[] parts = line.split("\\|", -1);
            out.add(new ParsedIoc(i + 1,
                    col(parts, 0), col(parts, 1), col(parts, 2), col(parts, 3),
                    col(parts, 4), col(parts, 5), col(parts, 6), col(parts, 7), line));
        }
        return out;
    }

    private static String col(String[] parts, int index) {
        if (index >= parts.length) {
            return null;
        }
        String value = parts[index].trim();
        return value.isEmpty() ? null : value;
    }
}
