# Scanner Remediation (Detection + Runtime Reliability) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复当前扫描器实现中的误判、并发与生命周期问题，补齐进度上报与调度缺口，并让核心测试稳定通过。

**Architecture:** 以“先锁定行为，再最小改动修复”为主线，优先修复会导致错误扫描结果的数据路径（probe + iterator + task pool），随后修复运行稳定性（reporter 生命周期、调度循环、指标上报）。每个任务都采用小步 TDD：先加失败测试，再做最小实现，再验证回归。

**Tech Stack:** Go 1.21, net/http, goroutine/channel, sync/atomic, testify, Cobra, resty

---

## File Structure (planned touch map)

- Modify: `free-proxy-scanner/internal/scanner/probe/probe.go`  
  责任: 代理识别规则（尤其 HTTP absolute-URI 误判、headers 置信规则）
- Modify: `free-proxy-scanner/internal/scanner/probe/proxy_features_test.go`  
  责任: probe 行为回归用例（普通 Web 不应判为代理）
- Modify: `free-proxy-scanner/internal/scanner/scanner_accuracy_test.go`  
  责任: 端到端识别准确率回归
- Modify: `free-proxy-scanner/pkg/utils/ip_iterator.go`  
  责任: CIDR 迭代逻辑修复（/31、/32、广播地址处理）
- Create: `free-proxy-scanner/pkg/utils/ip_iterator_test.go`  
  责任: iterator 边界测试
- Modify: `free-proxy-scanner/internal/scanner/scanner.go`  
  责任: 原始扫描器并发计数安全、计数语义正确性
- Modify: `free-proxy-scanner/internal/scanner/reporter/reporter.go`  
  责任: reporter ticker 生命周期可关闭
- Modify: `free-proxy-scanner/internal/scanner/reporter/reporter_test.go`  
  责任: reporter 关闭与并发行为测试
- Modify: `free-proxy-scanner/internal/scanner/ip_task_pool.go`  
  责任: in-flight 完成判定、结果队列消费路径、停止顺序
- Create: `free-proxy-scanner/internal/scanner/ip_task_pool_test.go`  
  责任: 任务池完成判定与结果不丢失测试
- Modify: `free-proxy-scanner/internal/scanner/ip_scanner.go`  
  责任: 与 task pool 新完成语义对齐
- Modify: `free-proxy-scanner/cmd/scanner/cmd/scan.go`  
  责任: task fetch 调度重构、任务进度持久化接线、心跳指标接线
- Create: `free-proxy-scanner/cmd/scanner/cmd/scan_test.go`  
  责任: 调度与进度上报行为测试
- Modify: `free-proxy-scanner/configs/config.example.yaml`  
  责任: 配置字段补全（scanner_type 等）
- Modify: `free-proxy-scanner/README.md`  
  责任: 行为与配置文档同步
- Optional cleanup: `free-proxy-scanner/internal/scanner/scanner.go`  
  责任: 清理未使用函数/字段（如未使用的 `isLikelyProxyService` / `workerPool`）

---

### Task 1: 修复 HTTP 误判（absolute URI 分支）

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/probe/probe.go`
- Test: `free-proxy-scanner/internal/scanner/probe/proxy_features_test.go`
- Test: `free-proxy-scanner/internal/scanner/scanner_accuracy_test.go`

- [ ] **Step 1: 写失败用例（普通 Web + absolute URI 请求）**
  
  在 `proxy_features_test.go` 增加 case：普通 Web 服务对 `GET http://...` 返回 200 HTML，不应被识别为 `http-proxy`。

- [ ] **Step 2: 运行测试确认失败**

  Run: `go test ./internal/scanner/probe -run TestAnalyzeProxyFeatures -count=1`  
  Expected: FAIL（普通 Web 被错误标记为代理）

- [ ] **Step 3: 最小修复实现**

  在 `probeHTTPAbsoluteURIProxy` 中改为“证据型判断”：
  - 仅在出现明确代理特征（Via / Proxy-* / CONNECT 专属状态）时返回 true
  - 删除仅凭 `html` / `example.com` 即认定代理的逻辑
  - 对普通 Web 200 + 内容型响应直接判 false

- [ ] **Step 4: 运行相关测试确认通过**

  Run: `go test ./internal/scanner/probe ./internal/scanner -run 'TestAnalyzeProxyFeatures|TestProxyIdentificationAccuracy|TestEndToEndProxyDetection' -count=1`  
  Expected: PASS

- [ ] **Step 5: Commit**

  `git add free-proxy-scanner/internal/scanner/probe/probe.go free-proxy-scanner/internal/scanner/probe/proxy_features_test.go free-proxy-scanner/internal/scanner/scanner_accuracy_test.go && git commit -m "fix(scanner): avoid classifying normal web servers as http proxies"`

---

### Task 2: 收敛 header 识别规则，降低泛化误判

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/probe/probe.go`
- Test: `free-proxy-scanner/internal/scanner/probe/proxy_features_test.go`

- [ ] **Step 1: 写失败用例（Server: Apache/nginx 但无代理头）**

  增加 case：仅出现常规 Web 头，不应触发 `hasProxyHeaders`。

- [ ] **Step 2: 运行测试确认失败**

  Run: `go test ./internal/scanner/probe -run TestHasProxyHeadersAdvanced -count=1`  
  Expected: FAIL（若当前规则过宽）

- [ ] **Step 3: 最小修复实现**

  调整 `hasProxyHeaders`:
  - 去掉模糊关键词（如裸 `apache`、裸 `cdn`）作为直接命中条件
  - 保留“键名级”代理头与明确代理软件签名（如 `server: squid`）

- [ ] **Step 4: 运行测试确认通过**

  Run: `go test ./internal/scanner/probe -count=1`  
  Expected: PASS

- [ ] **Step 5: Commit**

  `git add free-proxy-scanner/internal/scanner/probe/probe.go free-proxy-scanner/internal/scanner/probe/proxy_features_test.go && git commit -m "fix(probe): tighten proxy header heuristics to reduce false positives"`

---

### Task 3: 修复 CIDR 迭代边界（/31、/32）

**Files:**
- Modify: `free-proxy-scanner/pkg/utils/ip_iterator.go`
- Create: `free-proxy-scanner/pkg/utils/ip_iterator_test.go`

- [ ] **Step 1: 写失败测试**

  覆盖以下场景：
  - `10.0.0.1/32` 应只返回 `10.0.0.1`
  - `10.0.0.0/31` 应返回两个地址（RFC 3021）
  - 一般网段应跳过广播地址

- [ ] **Step 2: 运行测试确认失败**

  Run: `go test ./pkg/utils -run TestIPIterator -count=1`  
  Expected: FAIL

- [ ] **Step 3: 最小修复实现**

  在 `NewIPIteratorFromCIDR` 和 `Next` 中显式处理 /31 /32:
  - 不再无条件 `inc(startIP)`
  - 根据 mask bits 选择起止和是否跳过网络/广播

- [ ] **Step 4: 运行测试确认通过**

  Run: `go test ./pkg/utils -count=1`  
  Expected: PASS

- [ ] **Step 5: Commit**

  `git add free-proxy-scanner/pkg/utils/ip_iterator.go free-proxy-scanner/pkg/utils/ip_iterator_test.go && git commit -m "fix(utils): correct CIDR iterator behavior for /31 and /32"`

---

### Task 4: 修复原始扫描器并发计数数据竞争

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/scanner.go`
- Test: `free-proxy-scanner/internal/scanner/scanner_accuracy_test.go` (必要时补并发计数测试)

- [ ] **Step 1: 写/补并发计数测试（可选 race 定位）**

  目标：并发扫描时计数一致且无 data race。

- [ ] **Step 2: 运行 race 检测确认问题存在**

  Run: `go test -race ./internal/scanner -count=1`  
  Expected: 当前实现可能出现 race 或计数不稳定

- [ ] **Step 3: 最小修复实现**

  将 `scannedIPs` / `foundProxies` 改为 atomic 计数（`atomic.Int64` 或 `sync/atomic`），避免 goroutine 内直接 `*ptr++`。

- [ ] **Step 4: 运行验证**

  Run: `go test -race ./internal/scanner -count=1`  
  Expected: PASS（或至少无 race 报告）

- [ ] **Step 5: Commit**

  `git add free-proxy-scanner/internal/scanner/scanner.go && git commit -m "fix(scanner): remove concurrent counter race in original scan flow"`

---

### Task 5: 修复 Reporter goroutine 生命周期泄漏

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/reporter/reporter.go`
- Modify: `free-proxy-scanner/internal/scanner/reporter/reporter_test.go`

- [ ] **Step 1: 写失败测试（Close 后不再触发 flush loop）**

  增加 reporter 可关闭行为测试。

- [ ] **Step 2: 运行测试确认失败**

  Run: `go test ./internal/scanner/reporter -run TestReporter -count=1`  
  Expected: FAIL（当前无关闭机制）

- [ ] **Step 3: 最小修复实现**

  新增 `Close()`：
  - 内部 `stopCh` + `sync.Once`
  - `flushLoop` select 监听 stop
  - 扫描流程结束时调用 `Close`（替代仅 `Flush`）

- [ ] **Step 4: 运行测试确认通过**

  Run: `go test ./internal/scanner/reporter -count=1`  
  Expected: PASS

- [ ] **Step 5: Commit**

  `git add free-proxy-scanner/internal/scanner/reporter/reporter.go free-proxy-scanner/internal/scanner/reporter/reporter_test.go && git commit -m "fix(reporter): add lifecycle close to prevent ticker goroutine leaks"`

---

### Task 6: 修复 IPTaskPool 完成判定与结果丢失风险

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/ip_task_pool.go`
- Modify: `free-proxy-scanner/internal/scanner/ip_scanner.go`
- Create: `free-proxy-scanner/internal/scanner/ip_task_pool_test.go`

- [ ] **Step 1: 写失败测试（队列空但 worker 仍在跑时不能判完成）**

  覆盖：
  - in-flight 任务存在时 `IsTaskComplete` 必须为 false
  - `Stop` 前必须可观测到结果已处理

- [ ] **Step 2: 运行测试确认失败**

  Run: `go test ./internal/scanner -run 'TestIPTaskPool' -count=1`  
  Expected: FAIL

- [ ] **Step 3: 最小修复实现**

  在 task pool 中增加：
  - in-flight 计数（worker 取到任务 +1，结束 -1）
  - 独立结果消费/汇总协程或直接去除无消费者 resultQueue
  - `WaitForCompletion` 条件使用：iterators empty + queue empty + in-flight=0
  - `Stop` 顺序避免提前关闭导致结果丢弃

- [ ] **Step 4: 运行测试确认通过**

  Run: `go test ./internal/scanner -run 'TestIPTaskPool|TestTaskPool' -count=1`  
  Expected: PASS

- [ ] **Step 5: Commit**

  `git add free-proxy-scanner/internal/scanner/ip_task_pool.go free-proxy-scanner/internal/scanner/ip_scanner.go free-proxy-scanner/internal/scanner/ip_task_pool_test.go && git commit -m "fix(ip-pool): make task completion and result handling deterministic"`

---

### Task 7: 重构任务拉取调度，恢复 fetch_interval 语义

**Files:**
- Modify: `free-proxy-scanner/cmd/scanner/cmd/scan.go`
- Create: `free-proxy-scanner/cmd/scanner/cmd/scan_test.go`

- [ ] **Step 1: 写失败测试（fetch 周期可控）**

  目标：`taskLoop` 不应被内部无限循环长期阻塞；可在 ticker 周期触发下一次拉取。

- [ ] **Step 2: 运行测试确认失败**

  Run: `go test ./cmd/scanner/cmd -run TestTaskLoop -count=1`  
  Expected: FAIL

- [ ] **Step 3: 最小修复实现**

  将 `fetchAndScanTasks` 改为“单轮处理函数”：
  - 每次处理本地可恢复任务 + 一批新任务后返回
  - 由 `taskLoop` 的 ticker 驱动周期执行
  - 保持 context 可中断 sleep/retry

- [ ] **Step 4: 运行测试确认通过**

  Run: `go test ./cmd/scanner/cmd -run TestTaskLoop -count=1`  
  Expected: PASS

- [ ] **Step 5: Commit**

  `git add free-proxy-scanner/cmd/scanner/cmd/scan.go free-proxy-scanner/cmd/scanner/cmd/scan_test.go && git commit -m "refactor(scanner): make task fetch loop honor fetch interval"`

---

### Task 8: 接通任务进度持久化与扫描计数

**Files:**
- Modify: `free-proxy-scanner/cmd/scanner/cmd/scan.go`
- Modify: `free-proxy-scanner/internal/scanner/scanner.go`
- Modify: `free-proxy-scanner/internal/scanner/ip_scanner.go`
- Modify: `free-proxy-scanner/internal/scanner/reporter/reporter.go`
- Test: `free-proxy-scanner/pkg/task_manager/manager_test.go`
- Test: `free-proxy-scanner/cmd/scanner/cmd/scan_test.go`

- [ ] **Step 1: 写失败测试（任务执行中会更新 progress/scanned/found）**

  目标：本地持久化任务文件中的 `progress`、`scanned_count`、`found_count` 能变化。

- [ ] **Step 2: 运行测试确认失败**

  Run: `go test ./cmd/scanner/cmd ./pkg/task_manager -run 'TestTaskProgress|TestUpdateTaskProgress' -count=1`  
  Expected: FAIL

- [ ] **Step 3: 最小修复实现**

  - 为 scanner 暴露统计快照读取方法
  - 在扫描中或批次边界调用 `taskMgr.UpdateTaskProgress`
  - 原始 scanner 分支修正 `foundProxies` 统计逻辑
  - reporter 的 `scannedCount` 真正接入调用

- [ ] **Step 4: 运行测试确认通过**

  Run: `go test ./cmd/scanner/cmd ./pkg/task_manager ./internal/scanner -count=1`  
  Expected: PASS

- [ ] **Step 5: Commit**

  `git add free-proxy-scanner/cmd/scanner/cmd/scan.go free-proxy-scanner/internal/scanner/scanner.go free-proxy-scanner/internal/scanner/ip_scanner.go free-proxy-scanner/internal/scanner/reporter/reporter.go free-proxy-scanner/pkg/task_manager/manager_test.go free-proxy-scanner/cmd/scanner/cmd/scan_test.go && git commit -m "feat(scanner): persist task progress and accurate scan counters"`

---

### Task 9: 补齐注册/心跳机器指标采集

**Files:**
- Modify: `free-proxy-scanner/cmd/scanner/cmd/scan.go`
- Create: `free-proxy-scanner/cmd/scanner/cmd/metrics.go` (或同文件内私有函数)
- Test: `free-proxy-scanner/cmd/scanner/cmd/scan_test.go`

- [ ] **Step 1: 写失败测试（非零指标）**

  目标：`MemoryTotal`、`CPUUsage`、`MemoryUsage`、`TaskCount` 不再固定 0（允许在部分平台 fallback）。

- [ ] **Step 2: 运行测试确认失败**

  Run: `go test ./cmd/scanner/cmd -run TestHeartbeatMetrics -count=1`  
  Expected: FAIL

- [ ] **Step 3: 最小修复实现**

  - 抽象指标采集函数（便于 mock）
  - 注册时填充内存总量
  - 心跳时填充任务数与资源使用率（获取失败则降级但不 panic）

- [ ] **Step 4: 运行测试确认通过**

  Run: `go test ./cmd/scanner/cmd -run TestHeartbeatMetrics -count=1`  
  Expected: PASS

- [ ] **Step 5: Commit**

  `git add free-proxy-scanner/cmd/scanner/cmd/scan.go free-proxy-scanner/cmd/scanner/cmd/metrics.go free-proxy-scanner/cmd/scanner/cmd/scan_test.go && git commit -m "feat(scanner): report real machine metrics in register and heartbeat"`

---

### Task 10: 清理死代码并同步配置/文档

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/scanner.go`
- Modify: `free-proxy-scanner/configs/config.example.yaml`
- Modify: `free-proxy-scanner/README.md`

- [ ] **Step 1: 写检查项（编译 + 文档一致性）**

  定义检查：
  - 编译无未使用字段/函数告警
  - README 的流程与真实行为一致
  - config.example 包含 `scanner_type` 说明

- [ ] **Step 2: 执行检查确认现状**

  Run: `go test ./cmd/scanner/cmd ./internal/scanner -count=1`  
  Expected: 当前可能通过编译但文档/配置不一致

- [ ] **Step 3: 最小修复实现**

  - 删除或接入未使用成员（例如 `workerPool`、`isLikelyProxyService`）
  - 更新配置模板与 README 的启动/调度/测试说明

- [ ] **Step 4: 运行最终回归**

  Run: `go test ./internal/scanner/... ./pkg/... ./cmd/scanner/cmd -count=1`  
  Expected: PASS

- [ ] **Step 5: Commit**

  `git add free-proxy-scanner/internal/scanner/scanner.go free-proxy-scanner/configs/config.example.yaml free-proxy-scanner/README.md && git commit -m "chore(scanner): remove dead paths and align config/docs with runtime behavior"`

---

### Task 11: 最终验收与回归基线

**Files:**
- Modify: `free-proxy-scanner/README.md` (测试章节补充)
- Create: `free-proxy-scanner/docs/scanner-regression-checklist.md`

- [ ] **Step 1: 建立最小回归清单**

  包含：
  - 检测准确性
  - iterator 边界
  - task pool 完成判定
  - 调度/进度/心跳指标

- [ ] **Step 2: 执行分层测试**

  Run: `go test ./internal/scanner/probe ./internal/scanner ./pkg/utils ./internal/scanner/reporter ./cmd/scanner/cmd -count=1`  
  Expected: PASS

- [ ] **Step 3: 记录环境依赖测试说明**

  将 Goat 依赖测试单独标记为“需先启动测试服务”，避免与单元测试混淆。

- [ ] **Step 4: 运行一次全量（允许环境型失败单独归类）**

  Run: `go test ./... -count=1`  
  Expected: 核心模块 PASS；若 Goat 环境未起，明确记录为环境阻塞而非代码回归

- [ ] **Step 5: Commit**

  `git add free-proxy-scanner/docs/scanner-regression-checklist.md free-proxy-scanner/README.md && git commit -m "docs(scanner): add regression checklist and test environment notes"`

---

## Notes

- 所有任务按 TDD 执行，避免一次性大改。
- 每个任务完成后先跑对应最小测试，再进入下一任务。
- 若某任务触发跨模块影响，先补失败测试再改实现，避免静默回归。
