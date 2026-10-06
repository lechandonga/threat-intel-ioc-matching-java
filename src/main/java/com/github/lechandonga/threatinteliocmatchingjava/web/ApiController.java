package com.github.lechandonga.threatinteliocmatchingjava.web;

import com.github.lechandonga.threatinteliocmatchingjava.alert.AlertRecord;
import com.github.lechandonga.threatinteliocmatchingjava.alert.AlertService;
import com.github.lechandonga.threatinteliocmatchingjava.intel.IntelService;
import com.github.lechandonga.threatinteliocmatchingjava.intel.IntelSnapshot;
import com.github.lechandonga.threatinteliocmatchingjava.intel.RefreshReport;
import com.github.lechandonga.threatinteliocmatchingjava.match.MatchService;
import com.github.lechandonga.threatinteliocmatchingjava.match.TelemetryRequest;
import com.github.lechandonga.threatinteliocmatchingjava.match.TelemetryResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    private final IntelService intelService;
    private final MatchService matchService;
    private final AlertService alertService;

    public ApiController(IntelService intelService, MatchService matchService, AlertService alertService) {
        this.intelService = intelService;
        this.matchService = matchService;
        this.alertService = alertService;
    }

    /** 重新从本地文件加载全部情报源，原子发布新快照。 */
    @PostMapping("/intel/refresh")
    public RefreshReport refresh() {
        return intelService.refresh();
    }

    /** 查看当前快照版本、IOC 数量与各来源状态（含逐条拒绝原因）。 */
    @GetMapping("/intel/status")
    public Map<String, Object> status() {
        IntelSnapshot snapshot = intelService.snapshot();
        return Map.of(
                "builtAt", snapshot.builtAt(),
                "recordCount", snapshot.recordCount(),
                "sources", snapshot.sourceResults().values());
    }

    /** 投递一批终端遥测并返回逐条匹配结果（命中依据、过期/未生效状态、拒绝原因）。 */
    @PostMapping("/match")
    public Map<String, Object> match(@RequestBody TelemetryRequest request) {
        List<TelemetryResult> results = matchService.matchBatch(request.getBatchId(), request.getEvents());
        long alerts = results.stream().filter(r -> "MATCH".equals(safeStatus(r))).count();
        long rejected = results.stream().filter(r -> r.rejectionReason() != null).count();
        return Map.of(
                "batchId", request.getBatchId() == null ? "" : request.getBatchId(),
                "total", results.size(),
                "matched", alerts,
                "rejected", rejected,
                "results", results);
    }

    /** 查询告警，可按资产 / IOC 值过滤，openOnly=true 只看仍在抑制窗口内的。 */
    @GetMapping("/alerts")
    public List<AlertRecord> alerts(@RequestParam(required = false) String assetId,
                              @RequestParam(required = false) String ioc,
                              @RequestParam(required = false) Boolean openOnly) {
        return alertService.query(assetId, ioc, openOnly);
    }

    private static String safeStatus(TelemetryResult result) {
        return result.status() == null ? null : result.status().name();
    }
}
