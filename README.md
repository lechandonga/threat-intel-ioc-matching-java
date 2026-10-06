# 本地威胁情报接入与 IOC 匹配告警服务

基于 Spring Boot 3 / Java 21 的**纯本地**服务：用本地文件模拟多个威胁情报源和终端遥测，
通过 HTTP 提供情报刷新、遥测匹配和告警查询，不依赖任何外部服务。

## 运行

```bash
mvn spring-boot:run                 # 默认 8080 端口
SERVER_PORT=8090 mvn spring-boot:run
mvn test                            # 运行业务测试，日志按业务分组打印覆盖用例
mvn package && java -jar target/threat-intel-ioc-matching-java-1.0-SNAPSHOT.jar
```

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/intel/refresh` | 重新从本地文件加载全部情报源并原子发布新快照 |
| GET | `/api/intel/status` | 当前快照版本、IOC 数量、各来源加载状态与逐行拒绝原因 |
| POST | `/api/match` | 投递一批终端遥测，返回逐条匹配结果 |
| GET | `/api/alerts?assetId=&ioc=&openOnly=` | 查询告警（可按资产/IOC 过滤；`openOnly=true` 仅窗口内） |

`POST /api/match` 请求体：

```json
{
  "batchId": "batch-001",
  "events": [
    {"assetId": "host-1", "value": "www.evil-example.com",
     "observedAt": "2026-10-07T10:00:00Z"}
  ]
}
```

`observedAt` 可省略（默认服务端当前时间），支持 ISO-8601 与 epoch 毫秒；
它同时是抑制窗口的计时基准。响应中每条记录独立给出：

- `status`：`MATCH` / `EXPIRED` / `NOT_YET_VALID` / `NO_MATCH`；
- `evidence`：命中的**全部**情报依据（来源、优先级、判定、有效期、`effective`、
  `conflictWinner`、`matchKind`），一条遥测命中多条 IOC 时完整列出；
- `rejectionReason`：该遥测记录格式错误时的逐条拒绝原因，不影响同批其他记录。

## 支持的情报格式

在 `application.properties` 用 `threat-intel.sources[n].*` 配置来源：
`id`（唯一标识）、`path`（本地文件）、`format`、`priority`（越大越权威）。
内置三种格式解析器，全部归一到统一模型（类型、规范化值、判定、有效期、来源）：

### 1. `json-feed`（简易 JSON 情报）

```json
{"indicators": [
  {"type": "sha256", "value": "e3b0...b855", "verdict": "malicious",
   "severity": "high", "validFrom": "2026-01-01T00:00:00Z",
   "validUntil": "2027-01-01T00:00:00Z", "firstSeen": "2026-09-01T00:00:00Z",
   "description": "trojan"}
]}
```

### 2. `csv`（管道分隔，首行表头，`#` 注释）

```
type|value|verdict|severity|validFrom|validUntil|firstSeen|description
domain|evil-example.com|malicious|high||||
cidr|10.10.0.0/16|suspicious|||||
```

### 3. `stix-bundle`（STIX 2.1 Bundle 子集）

支持 indicator 对象的三类 pattern：

- `[file:hashes.'SHA-256' = '...']`（SHA-256 / SHA-1 / MD5）
- `[domain-name:value = 'example.com']`
- `[ipv4-addr:value = '10.0.0.0/8']`（单 IP 或 CIDR）

判定从 `labels` / `indicator_types` 推断：`malicious-activity` → malicious，
`suspicious-activity`/`anomaly` → suspicious，`benign` → clean，缺省 malicious；
时间取 `valid_from` / `valid_until` / `created`。

### 字段取值约定

- `type`：`md5`/`sha1`/`sha256`、`domain`、`ip`、`cidr`；
- `verdict`：`malicious` / `suspicious` / `clean`（兼容 `blacklist`、`graylist`、
  `whitelist`、`benign`、数字 2/1/0 等常见写法）；
- 时间：ISO-8601（如 `2026-10-01T00:00:00Z`）或 epoch 毫秒，空值表示无边界。

示例文件见 `src/main/resources/intel-sources/`。

## 冲突取舍规则（确定且可复现）

同一 IOC（同类型 + 规范化值相同）被多个来源给出不同判定时，按以下顺序裁决：

1. **判定等级高者胜**：`MALICIOUS(2) > SUSPICIOUS(1) > CLEAN(0)`；
2. 同等级时，**来源 `priority` 高者胜**（配置中数值越大越权威）；
3. 仍相同时，`firstSeen` **更早者胜**；
4. 仍相同时，`sourceId` **字典序靠前者胜**。

裁决结果（`winner`）以及每个来源的原始判定都会保留，匹配返回的 `evidence`
中以 `conflictWinner=true` 标出被选中的依据，冲突取舍全程可追溯。

## 有效期规则

- 有效期为半开区间 `[validFrom, validUntil)`：到期**时刻**即过期，生效**时刻**即命中；
- 匹配状态四态严格区分：`MATCH`（存在生效记录）、`EXPIRED`（情报存在但均已过期）、
  `NOT_YET_VALID`（情报存在但均未生效）、`NO_MATCH`（情报库不存在）；
- 同一 IOC 只要有一条来源记录生效即为 `MATCH`，同时列出过期/未生效的其他依据。

## 匹配语义

- **哈希**（MD5/SHA-1/SHA-256）：十六进制大小写归一后精确匹配；
- **域名**：精确域命中，且**子域名命中父域**（按标签边界 `.` 连接）；
  `notevil-example.com`、`evil-example.org`、`evil-example.com.evil.net` 等相似域名
  不会命中 `evil-example.com`；
- **IP/CIDR**：单 IP 精确命中；IP 落在情报 CIDR 内命中（`matchKind=IP_WITHIN_INDICATOR_CIDR`），
  网段按网络位严格比较，网络地址/广播地址在段内、相邻网段边界外地址不命中；
  CIDR 情报必须是规范网络地址（如 `10.0.0.5/24` 会被拒绝并提示正确写法）；
  CIDR 遥测只与完全相同的网段情报匹配，避免子网/超网歧义；
- **逐记录拒绝**：未知类型、错误哈希长度、非法域名、非法/非规范 CIDR、未知 verdict、
  非法时间、`validFrom >= validUntil` 等都会在刷新报告中按**行号**给出具体原因，
  其余记录正常加载；遥测同理，坏记录不影响整批。

## 来源失败容错

文件缺失、不可读或顶层结构损坏属于**来源整体失败**（区别于“部分记录被拒绝”）：
本次刷新会**保留该来源在上一版快照中的全部已生效情报**，其他来源照常更新，
失败明细与“保留了多少旧数据”写入刷新报告，绝不清空。

## 告警抑制与去重

- 抑制键：`assetId | iocType | iocValue`（同一资产 + 同一 IOC）；
- 窗口长度：`threat-intel.suppression-window-seconds`，默认 **600 秒**：

  ```properties
  threat-intel.suppression-window-seconds=600
  ```
  也可用环境变量 `SUPPRESSION_WINDOW_SECONDS` 覆盖。
- 命中时间落在当前窗口 `[windowStart, windowEnd)` 内只保留一条告警，
  累计 `hitCount`、`firstSeen/lastSeen` 时间范围和 `batchIds`；
  窗口结束后的下一次命中开启新窗口（产生新告警，历史窗口保留可查）；
- **批次幂等**：同一 `batchId` 对同一抑制键的重复投递直接忽略，
  不产生重复告警、不重复计数。

## 并发一致性

情报以**不可变快照**（`IntelSnapshot`）形式存在，刷新时先在新结构中完成全部加载、
归一、裁决与索引构建，再通过 `AtomicReference` 原子替换；匹配全程只持有快照引用，
因此刷新进行中的每次查询只能看到刷新前或刷新后的完整状态，不存在半刷新中间结果
（见 `ConcurrentRefreshTest`）。

## 验证方法

```bash
mvn test
```

测试日志以 `BUSINESS-COVERAGE` 按业务分组，直接展示覆盖的业务及用例通过情况：

| 业务分组 | 测试类 | 关键用例 |
| --- | --- | --- |
| 情报冲突的确定性取舍 | `ConflictResolutionTest` | 判定等级优先于来源优先级；同等级按 priority/firstSeen/sourceId 裁决 |
| 有效期边界 | `ValidityBoundaryTest` | 半开区间边界、过期/未生效/不存在三态区分、部分生效 |
| IOC 匹配语义 | `MatchingSemanticsTest` | 子域命中、相似域名零误报、CIDR 首尾与相邻边界、多依据列出、哈希与非法值拒绝 |
| 来源失败容错 | `SourceFailureTest` | 文件缺失/JSON 损坏保留旧数据、逐行可区分拒绝原因 |
| 告警抑制与幂等 | `SuppressionAndDedupTest` | 窗口内合并计数与时间范围、重复批次幂等、窗口外新告警 |
| 并发快照一致性 | `ConcurrentRefreshTest` | 并发刷新/查询无中间态 |
| HTTP API 端到端 | `HttpApiIntegrationTest` | 刷新→匹配→告警全链路、坏请求体 400 |

手工冒烟：

```bash
mvn package -DskipTests
SERVER_PORT=8090 java -jar target/threat-intel-ioc-matching-java-1.0-SNAPSHOT.jar

curl -s -X POST localhost:8090/api/intel/refresh
curl -s -X POST localhost:8090/api/match -H 'Content-Type: application/json' -d '{
  "batchId":"demo-1",
  "events":[
    {"assetId":"host-1","value":"www.evil-example.com"},
    {"assetId":"host-1","value":"notevil-example.com"},
    {"assetId":"host-2","value":"10.10.255.255"}
  ]}'
curl -s "localhost:8090/api/alerts?openOnly=true"
```
