package com.github.lechandonga.threatinteliocmatchingjava.normalize;

import com.github.lechandonga.threatinteliocmatchingjava.config.IntelSourceProperties;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * 情报源解析器：只负责把不同文件格式拆成统一的 {@link ParsedIoc} 行记录。
 * 文件不可读 / 顶层结构损坏视为源整体失败，由上层决定保留旧数据。
 */
public interface IntelSourceParser {

    IntelSourceProperties.Format format();

    List<ParsedIoc> parse(Path file) throws IOException;

    static String readString(Path file) throws IOException {
        return Files.readString(file);
    }
}
