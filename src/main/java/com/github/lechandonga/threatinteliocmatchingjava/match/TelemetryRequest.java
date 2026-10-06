package com.github.lechandonga.threatinteliocmatchingjava.match;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * POST /api/match 请求体：
 * <pre>{@code
 * {"batchId":"batch-001", "events":[
 *   {"assetId":"host-1","value":"evil.example.com","observedAt":"2026-10-07T10:00:00Z"}
 * ]}
 * }</pre>
 * observedAt 可省略，默认按服务端当前时间（也是抑制窗口的计算基准）。
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class TelemetryRequest {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Event {
        private String assetId;
        private String value;
        private String observedAt;

        public String getAssetId() { return assetId; }
        public void setAssetId(String assetId) { this.assetId = assetId; }
        public String getValue() { return value; }
        public void setValue(String value) { this.value = value; }
        public String getObservedAt() { return observedAt; }
        public void setObservedAt(String observedAt) { this.observedAt = observedAt; }
    }

    private String batchId;
    private List<Event> events;

    public String getBatchId() { return batchId; }
    public void setBatchId(String batchId) { this.batchId = batchId; }
    public List<Event> getEvents() { return events; }
    public void setEvents(List<Event> events) { this.events = events; }
}
