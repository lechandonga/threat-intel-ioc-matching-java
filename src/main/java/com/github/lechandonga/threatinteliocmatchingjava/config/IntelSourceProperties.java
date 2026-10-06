package com.github.lechandonga.threatinteliocmatchingjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 本地情报源配置（application.properties 中 {@code threat-intel.sources.*}）。
 */
@ConfigurationProperties(prefix = "threat-intel")
public class IntelSourceProperties {

    public enum Format { JSON_FEED, CSV, STIX_BUNDLE }

    public static class Source {
        /** 来源唯一标识，也是冲突裁决最后一级 tie-break 依据。 */
        private String id;
        /** 本地文件路径。 */
        private Path path;
        /** 文件格式：json-feed / csv / stix-bundle。 */
        private Format format;
        /** 来源优先级，数值越大越权威；冲突判定同等级时高者胜。 */
        private long priority = 0;

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public Path getPath() { return path; }
        public void setPath(Path path) { this.path = path; }
        public Format getFormat() { return format; }
        public void setFormat(Format format) { this.format = format; }
        public long getPriority() { return priority; }
        public void setPriority(long priority) { this.priority = priority; }
    }

    private List<Source> sources = new ArrayList<>();
    /** 告警抑制窗口（秒），同一资产+同一 IOC 在窗口内只产生一条告警。 */
    private long suppressionWindowSeconds = 600;
    /** 启动时是否自动加载一次情报。 */
    private boolean loadOnStartup = true;

    public List<Source> getSources() { return sources; }
    public void setSources(List<Source> sources) { this.sources = sources; }
    public long getSuppressionWindowSeconds() { return suppressionWindowSeconds; }
    public void setSuppressionWindowSeconds(long suppressionWindowSeconds) {
        this.suppressionWindowSeconds = suppressionWindowSeconds;
    }
    public boolean isLoadOnStartup() { return loadOnStartup; }
    public void setLoadOnStartup(boolean loadOnStartup) { this.loadOnStartup = loadOnStartup; }
}
