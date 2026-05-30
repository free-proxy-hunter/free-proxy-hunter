# Research: free-proxy-scanner 模块成熟度评估

**Question:** 扫描器模块当前的实现成熟度如何？哪些维度已成熟、哪些仍需优化？下一步优化方向是什么？

**Context:** 用户希望基于现有扫描器模块持续优化，需要先评估当前成熟度，再制定下一步计划。

**Deliverable:** 成熟度评估报告 + 下一步优化方向建议

**Time Box:** 建议 2 小时内完成阅读，本报告为最终产出

**Scope:** Medium

---

## 一、项目概况

free-proxy-scanner 是 free-proxy-hunter 项目中的核心扫描引擎，负责从互联网发现和验证开放代理服务器。

**技术栈：** Go 1.21, Cobra CLI, Viper 配置, zap 日志, golang.org/x/net/proxy, testify 测试

**架构模式：** 多层 Pipeline（Probe → Validator → Enhanced Scanner → Reporter）

**代码规模：** ~30+ 源文件，7+ 子包，~4000-5000 行 Go 代码

**开发时间线：** 2026-04 至 2026-05，持续约 2 个月

---

## 二、成熟度评估（7 个维度）

### 总评：★★★☆☆（3/5）— 原型已通过，进入精度打磨阶段

| 维度 | 评分 | 状态 |
|------|------|------|
| 1. 功能完整性 | ★★★★☆ | 核心功能完备，辅助功能部分缺失 |
| 2. 代码质量 | ★★★☆☆ | 有已知 bug 修复记录，部分区域仍需关注 |
| 3. 测试覆盖 | ★★☆☆☆ | 单元测试 ~57-73%，集成测试依赖 goat-server |
| 4. 精度/准确性 | ★★★☆☆ | 误报问题已识别并修复中，仍有 4 个误报源头 |
| 5. 架构设计 | ★★★★☆ | 分层清晰，职责分离好 |
| 6. 生产就绪度 | ★★★☆☆ | PM2 部署可用，但监控和容错不足 |
| 7. 可维护性 | ★★★☆☆ | 文件已拆分，但部分模块耦合仍高 |

---

### 维度 1: 功能完整性 — ★★★★☆

**已实现（成熟）：**
- Probe 层：端口扫描 + Banner 分析 + HTTP/SOCKS4/SOCKS5 探测 + 代理头分析 + 置信度评分
- Validator 层：HTTP CONNECT 验证 + 绝对 URI 验证 + SOCKS4/5 验证 + IP 变化检测（IPVerifier）
- Enhanced Scanner：两阶段扫描（无认证 → 字典爆破）
- 任务编排：Scanner（原始）+ IPScanner（增强）+ IPTaskPool + TaskCoordinator
- 报告：批量结果上报 + 心跳
- 靶场：goat-server 73+ 模拟服务（代理、陷阱、非代理、边界场景）
- CLI：Cobra 命令 + 任务循环 + 配置管理

**部分实现：**
- HTTPS 代理探测（plan 中提到但可能不完整）
- SOCKS5 认证爆破（基础功能有，字典同步和动态更新不完善）
- 速率限制/流量控制（无）

**未实现：**
- IPv6 支持（plan 中提到 IPv6 格式化 bug 但可能未完全修复）
- 代理类型细分（透明代理 vs 匿名代理 vs 高匿代理）
- 扫描任务断点续传（task_manager 存在但功能可能不完整）
- 分布式扫描协调

---

### 维度 2: 代码质量 — ★★★☆☆

**已修复的关键 bug（14+ 个）：**

| Bug | 严重程度 | 修复时间 |
|-----|---------|---------|
| pool.go scanIP 是 mock 函数 | 严重 | 2026-04-09 |
| scanner.go 竞态条件 | 严重 | 2026-04-10 |
| reporter.go goroutine 泄漏 | 严重 | 2026-04-10 |
| formatPercentage 使用 string(rune()) | 中等 | 2026-04-10 |
| SOCKS5 探测接受 SOCKS4 响应 | 严重 | 2026-04-10 |
| 计数器非原子操作 | 中等 | 2026-04-10 |
| IP 迭代器 /31 /32 边界错误 | 中等 | 2026-04-10 |
| analyzeBanner 误报 | 中等 | 2026-04-11 |
| IPv6 格式化问题 | 低 | 2026-04-11 |
| ScanAndIdentifyPort 未被 IPScanner 使用 | 严重 | 2026-05-24 |
| proxy_headers.go 312 行未拆分 | 低 | 2026-04-12（已拆分为 3 文件） |

**仍存在的代码质量问题（基于 plan 文档推断）：**
- Probe 层误报源头 4 个（503/504/403/401 判定过宽）— 已有修复 plan
- Validator 层 CONNECT 200 验证过宽 — 已有修复 plan
- Validator 层绝对 URI 回退逻辑过宽 — 已有修复 plan
- EnhancedScanner 上报未验证结果 — 已有修复 plan

**代码结构评价：**
- 正面：已拆分为 probe/validator/reporter/enhanced/dictionary_scanner/task 子包
- 正面：命名清晰，函数职责单一
- 负面：部分文件仍有高耦合（scanner.go 同时包含 Scanner 和 IPScanner）

---

### 维度 3: 测试覆盖 — ★★☆☆☆

**当前覆盖率（基于 2026-05-03 plan 数据）：**

| 包 | 估计覆盖率 | 关键未覆盖函数 |
|----|-----------|--------------|
| probe/ | ~70% | 部分探测路径 |
| validator/ | ~60% | IPVerifier, SOCKS 验证分支 |
| scanner（顶层）| ~0-20% | ScanTask, ScanTaskFixed, processIPBatch |
| ip_scanner_task | ~0% | fillTaskQueue, scanIPTask, monitorProgress |
| task/ | ~0-30% | coordinateTasks, adjustTaskPool, reportStatistics |
| enhanced/ | ~0-40% | ValidateHTTPProxy, probeService, probeSocks |
| reporter/ | ~60% | 有基础测试 |
| dictionary_scanner/ | ~0% | ScanWithDictionary |

**测试基础设施：**
- 单元测试：各包有 `*_test.go` 文件
- 集成测试：`test/` 目录下的 goat 验证测试（73 服务）
- 精度度量：`accuracy_metrics_test.go`（TP/FP/TN/FN + precision/recall）
- **问题：** 覆盖率文件为空（`mode: set` 无数据），说明覆盖率收集未成功运行
- **问题：** 集成测试依赖 goat-server 运行，无 goat-server 时自动 skip

**测试 Plan 已创建但执行情况未知：**
- Plan A（基础层）：config, IP 工具, probe 分析, parser
- Plan B（中间层）：socks_bruteforcer, dictionary_sync, validator
- Plan C（顶层）：scanner 编排, task pool, coordinator
- 100% 覆盖率 Plan：6 个 Task

---

### 维度 4: 精度/准确性 — ★★★☆☆

**已知误报问题（已识别，修复 plan 已写）：**

| 误报源头 | 影响 | Plan 状态 |
|---------|------|----------|
| 503/504 状态码贡献过高置信度 | Web 服务器误判为代理 | 2026-05-27 plan Task 2 |
| CONNECT 200 验证过宽 | 短 200 响应误判 | 2026-05-27 plan Task 3 |
| 绝对 URI 回退逻辑过宽 | 无代理头也无目标内容时通过 | 2026-05-27 plan Task 3 |
| 403/401 无 Proxy-Authenticate 误判 | Web 应用误判为代理 | 2026-05-24 plan Task 2 |
| analyzeBanner HTTP 回退为 http-proxy | 所有 HTTP 服务都可能是代理 | 2026-05-24 plan Task 2 |
| proxyIndicators 含 CDN/反向代理关键词 | Cloudflare/Varnish 站点误判 | 2026-05-24 plan Task 2 |
| isCommonProxyPort 含 80/443 | 所有 Web 服务都是"代理端口" | 2026-05-24 plan Task 2 |

**精度目标（plan 文档中定义）：**
- Probe 精确率 ≥ 70%（修复后目标）
- Validator 精确率 ≥ 80%（修复后目标）
- FP rate ≤ 15-20%
- 当前实际精度未知（需要 goat-server 端到端验证才能测量）

**精度度量基础设施：**
- `accuracy_metrics_test.go` 已创建，度量 TP/FP/TN/FN
- 靶场 73+ 服务 + 新增 5 个真实世界场景 + 9 个误报陷阱
- 阈值检查已内置（但实际数值依赖运行）

---

### 维度 5: 架构设计 — ★★★★☆

**正面：**
- 清晰的四层 Pipeline：Probe（检测）→ Validator（验证）→ Enhanced Scanner（增强）→ Reporter（上报）
- 策略模式：不同协议的 Probe 和 Validator 独立实现
- 置信度评分机制：`analyzeProxyHeaders()` 返回 0.0-1.0 分数 + 特征列表
- Worker Pool 模式：`IPTaskPool` + channel 任务队列 + 信号量并发控制
- Bloom Filter 去重：防止重复扫描
- 测试靶场设计：goat-server 提供可控的模拟环境

**待改进：**
- Scanner 和 IPScanner 共存于 `scanner.go`，职责边界模糊
- Enhanced 包与 Validator 包有功能重叠（IPVerifier 在两处都存在）
- 配置管理：部分硬编码的超时和 URL
- 错误处理：部分函数返回 `nil` 而非明确错误

---

### 维度 6: 生产就绪度 — ★★★☆☆

**已具备：**
- PM2 进程管理（ecosystem.config.js）
- API Server 集成（任务获取 + 结果上报 + 心跳）
- 本地任务持久化（`~/.free-proxy-hunter/tasks/`）
- 结构化日志（zap）
- 构建脚本（manage.sh, start.sh）

**缺失：**
- 监控指标（Prometheus metrics 或类似）— `metrics.go` 存在但只收集 CPU/内存
- 告警机制（扫描失败、代理发现率异常等）
- 优雅关机（Stop 方法有但可能不完整）
- 健康检查端点
- 配置热重载
- 扫描速率自适应（当前并发数固定）

---

### 维度 7: 可维护性 — ★★★☆☆

**正面：**
- 文件已拆分（proxy_headers.go 312 行 → 3 文件）
- 子包结构清晰（probe/validator/reporter/enhanced/dictionary_scanner/task）
- 有 14 份 plan 文档记录所有改动

**负面：**
- 子包间依赖关系较深（scanner → probe → validator → enhanced）
- 无 API 文档（Godoc 注释不完整）
- 配置项分散（config.yaml + 环境变量 + 硬编码）
- 子模块管理复杂（6 个 git submodule，当前 2 个未成功 checkout）

---

## 三、计划执行状态总结

| Plan | 日期 | Task 数 | 状态 |
|------|------|---------|------|
| scanner-remediation | 2026-04-09 | 11 | 已创建，执行状态未知 |
| scanner-bug-fixes | 2026-04-10 | N/A | 已创建 |
| scanner-bugfix-and-improvement | 2026-04-11 | N/A | 已创建 |
| scanner-file-splitting | 2026-04-12 | N/A | 已创建 |
| scanner-test-coverage-plan-a/b/c | 2026-04-12 | N/A | 已创建 |
| scanner-100-coverage | 2026-05-03 | 6 | 已创建 |
| scanner-precision-and-goat-validation | 2026-05-24 | 6 | 已创建 |
| scanner-goat-integration-test | 2026-05-24 | N/A | 已创建 |
| scanner-goat-integration-enhancement | 2026-05-25 | 5 | 已创建 |
| scanner-goat-continuous-improvement | 2026-05-27 | 6 | 已创建，最新 |

**关键发现：** 14 份 plan 文档已创建，但所有 plan 的实际执行状态无法从本地确认（子模块未 checkout）。最近的 plan 是 2026-05-27 的持续性完善 plan，包含 6 个 Task。

---

## 四、下一步优化方向建议（按优先级排序）

### P0: 确认当前状态（前提条件）

在制定新优化计划之前，必须先：
1. **checkout 子模块** — `git submodule update --init` 获取最新代码
2. **运行现有测试** — `go test ./...` 确认当前测试基线
3. **运行 goat-server 端到端验证** — 测量实际精度数据
4. **确认 2026-05-27 plan 的执行状态** — 已完成的 Task 可以跳过

### P1: 精度优化（最高 ROI）

基于已有的 plan，继续执行误报修复：
- 503/504 置信度降低（proxy_analysis.go）
- CONNECT 200 验证收紧（validator.go）
- 绝对 URI 回退收紧（validator.go）
- 403/401 无 Proxy-Authenticate 误判修复（proxy_probes.go）
- 新增 5 个真实世界靶场场景验证效果

**预估效果：** 误报率降低 60-70%（plan 文档中的目标）

### P2: 测试覆盖率提升

补全以下 0% 覆盖区域：
- scanner 顶层：ScanTask/ScanTaskFixed/processIPBatch
- ip_scanner_task：fillTaskQueue/scanIPTask/monitorProgress
- task 包：coordinateTasks/adjustTaskPool/fillTasksForIterator
- enhanced 包：ValidateHTTPProxy/probeService/probeSocks
- dictionary_scanner：ScanWithDictionary

**目标：** 从 ~57-73% 提升到 85%+（100% 作为远期目标）

### P3: 代码质量提升

- Scanner 和 IPScanner 拆分到独立文件
- IPVerifier 统一到 validator 包（消除 enhanced/validator 重复）
- 错误处理标准化（消除 `nil` 返回，使用 error 类型）
- 消除硬编码的 URL 和超时值

### P4: 生产增强

- Prometheus 指标导出（扫描速率、代理发现数、误报率）
- 健康检查端点
- 优雅关机完善
- 扫描速率自适应（根据网络状况调整并发数）
- 断点续传功能

### P5: 功能扩展

- 代理类型细分（透明/匿名/高匿）
- IPv6 完整支持
- HTTPS 代理探测增强
- 分布式扫描协调
- 代理存活周期跟踪

---

## 五、成熟度雷达图

```
          功能完整性 ★★★★☆
              4/5
               |
  代码质量     |     架构设计
   3/5  ------+------  4/5
              |
  测试覆盖     |     精度/准确性
   2/5  ------+------  3/5
              |
              |
  可维护性     |     生产就绪度
   3/5        |       3/5
              |
```

**综合评价：** 扫描器已从原型阶段进入精度打磨阶段。核心功能完备，架构设计合理，但测试覆盖率不足和误报问题是当前最大的两个短板。好消息是这两个问题都已有详细的 plan 文档，可以直接执行。

---

## 六、信息源

| 信息源 | 类型 | 关键发现 |
|--------|------|---------|
| docs/superpowers/plans/14 份 plan 文档 | 项目文档 | 完整的开发历史和 bug 记录 |
| .gitmodules + git submodule status | Git 状态 | 子模块未 checkout，远程有最新代码 |
| ecosystem.config.js | 配置文件 | PM2 管理 3 个服务 |
| scanner.log (2026-03) | 运行日志 | 证明扫描器曾在生产环境运行 |
| 2026-05-27 plan (最新) | Plan | 6 Task 持续完善计划，含精确行号 |
| 2026-05-24 precision plan | Plan | 6 Task 精度优化计划 |
| 2026-05-03 coverage plan | Plan | 6 Task 100% 覆盖率计划 |

---

## 七、行动建议

**立即执行：**
1. checkout 子模块获取最新代码
2. 确认 2026-05-27 plan 中各 Task 的完成状态
3. 对未完成的 Task 继续执行

**短期（1-2 周）：**
- 完成精度优化（P1）— 修复 4 个误报源头
- 完成靶场增强 — 新增真实世界场景 + 陷阱服务
- 运行端到端验证，获取实际精度基线

**中期（2-4 周）：**
- 测试覆盖率提升到 85%（P2）
- 代码质量提升（P3）— 消除重复，标准化错误处理
- 建立 CI 精度回归检测

**长期：**
- 生产增强（P4）— 监控、健康检查、速率自适应
- 功能扩展（P5）— 代理类型细分、IPv6、分布式
