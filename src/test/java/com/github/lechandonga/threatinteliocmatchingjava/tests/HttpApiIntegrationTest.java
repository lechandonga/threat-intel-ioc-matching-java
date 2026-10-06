package com.github.lechandonga.threatinteliocmatchingjava.tests;

import com.github.lechandonga.threatinteliocmatchingjava.tests.coverage.BusinessTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@BusinessTest("HTTP API 端到端")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class HttpApiIntegrationTest {

    @TempDir
    static Path dir;

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("threat-intel.suppression-window-seconds", () -> 600);
        registry.add("threat-intel.sources[0].id", () -> "http-src");
        registry.add("threat-intel.sources[0].format", () -> "json-feed");
        registry.add("threat-intel.sources[0].priority", () -> 10);
        registry.add("threat-intel.sources[0].path", () -> dir.resolve("f.json").toString());
    }

    @BeforeAll
    static void seed() throws Exception {
        Files.writeString(dir.resolve("f.json"), """
                {"indicators":[
                  {"type":"domain","value":"api-evil.test","verdict":"malicious","firstSeen":"2026-09-01T00:00:00Z"}
                ]}
                """);
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    @DisplayName("刷新 -> 匹配 -> 告警查询 全链路，并验证重复投递幂等")
    void refreshMatchAlerts() {
        ResponseEntity<String> refreshed = rest.postForEntity(url("/api/intel/refresh"), null, String.class);
        assertEquals(200, refreshed.getStatusCode().value());
        assertTrue(refreshed.getBody().contains("http-src"));

        String body = """
                {"batchId":"http-b1","events":[
                  {"assetId":"web-1","value":"www.api-evil.test"},
                  {"assetId":"web-1","value":"bad value !! no tld"},
                  {"assetId":"web-2","value":"clear.test"}
                ]}
                """;
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<String> matched = rest.postForEntity(
                url("/api/match"), new HttpEntity<>(body, headers), String.class);
        assertEquals(200, matched.getStatusCode().value());
        String json = matched.getBody();
        assertTrue(json.contains("MATCH"));
        assertTrue(json.contains("SUBDOMAIN_OF_INDICATOR_DOMAIN"));
        assertTrue(json.contains("NO_MATCH"));
        assertTrue(json.contains("rejectionReason"));

        ResponseEntity<String> replayed = rest.postForEntity(
                url("/api/match"), new HttpEntity<>(body, headers), String.class);
        assertTrue(replayed.getBody().contains("\"matched\":1"));

        ResponseEntity<String> alerts = rest.getForEntity(
                url("/api/alerts?assetId=web-1&openOnly=true"), String.class);
        assertTrue(alerts.getBody().contains("api-evil.test"));
        assertTrue(alerts.getBody().contains("\"hitCount\":1"));
    }

    @Test
    @DisplayName("损坏的 JSON 请求体返回 400 与可识别错误码")
    void malformedBodyIs400() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<String> response = rest.postForEntity(
                url("/api/match"), new HttpEntity<>("{not json", headers), String.class);
        assertEquals(400, response.getStatusCode().value());
        assertTrue(response.getBody().contains("MALFORMED_REQUEST_BODY"));
    }
}
