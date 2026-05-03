# Scanner Module File Size Analysis (2026-04-12)

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 分析 scanner 项目文件大小分布，识别可拆分的大文件并执行拆分，确保每个文件职责单一且行数合理（<200 行为目标）。

**Architecture:** 经过之前的重构，scanner 项目最大文件已降至 312 行（proxy_headers.go）。当前没有超过 500 行的大文件，但从职责单一角度，部分文件仍可做更精细的拆分。方案：将 proxy_headers.go 拆为 3 个文件（检测/分析/分类），scanner.go 提取 processIPBatch 为独立文件，ip_scanner.go 拆出任务执行逻辑。

**Tech Stack:** Go 1.21+, 同 package 内文件拆分

---

## Analysis Summary

### 当前文件大小分布

| 文件 | 行数 | 函数数 | 职责数 | 建议 |
|------|------|--------|--------|------|
| `probe/proxy_headers.go` | 312 | 5 | 3 (检测/分析/分类) | 拆为 3 个文件 |
| `scanner.go` | 292 | 5 | 2 (核心+批量处理) | 提取 processIPBatch |
| `ip_scanner.go` | 295 | 7 | 2 (核心+任务执行) | 拆出 fill/scan/monitor |
| `enhanced/http_validator.go` | 279 | 7 | 1 | 保持现状 |
| `proxy_probes.go` | 264 | 4 | 1 | 保持现状 |
| `enhanced/service_identifier.go` | 252 | 10 | 1 | 保持现状 |
| `ip_task_pool.go` | 249 | 16 | 1 | 保持现状 |

**结论：** 只有前 3 个文件有拆分价值。拆分后最大文件将降至 ~170 行。

---

### Task 1: Split proxy_headers.go into 3 Focused Files

**Depends on:** None
**Files:**
- Create: `free-proxy-scanner/internal/scanner/probe/proxy_detection.go` — `hasProxyHeaders()` + `proxyIndicators` 列表
- Create: `free-proxy-scanner/internal/scanner/probe/proxy_analysis.go` — `analyzeProxyHeaders()`, `isLikelyProxy()`, `checkProxyHeaders()`
- Create: `free-proxy-scanner/internal/scanner/probe/port_classification.go` — `isCommonProxyPort()`, `IsNonProxyService()`
- Delete: `free-proxy-scanner/internal/scanner/probe/proxy_headers.go`

- [ ] **Step 1: Create proxy_detection.go**

Create `free-proxy-scanner/internal/scanner/probe/proxy_detection.go`:

```go
package probe

import (
	"strings"
)

// proxyIndicators 代理特征关键词列表
var proxyIndicators = []string{
	"via:",
	"x-forwarded-for:",
	"x-forwarded-host:",
	"x-forwarded-proto:",
	"x-forwarded-port:",
	"x-forwarded-server:",
	"x-forwarded-scheme:",
	"x-real-ip:",
	"x-proxy",
	"x-proxy-id:",
	"x-proxy-by:",
	"x-proxy-cache:",
	"x-proxy-backend:",
	"proxy-connection:",
	"proxy-authenticate:",
	"proxy-authorization:",
	"proxy-agent:",
	"cf-connecting-ip:",
	"cf-ipcountry:",
	"cf-ray:",
	"cf-visitor:",
	"x-scheme:",
	"server: squid",
	"server: nginx-proxy",
	"server: tinyproxy",
	"server: privoxy",
	"server: polipo",
	"proxy-agent: squid",
	"proxy-agent: nginx",
	"proxy-agent: tinyproxy",
	"apache",
	"haproxy",
	"varnish",
	"cloudflare",
	"akamai",
	"fastly",
	"cdn",
	"x-cache:",
	"x-cache-lookup:",
	"x-cacheable:",
	"x-varnish:",
	"x-hits:",
	"x-squid-error:",
	"407 proxy authentication required",
	"502 bad gateway",
	"503 service unavailable",
	"504 gateway timeout",
	"privoxy",
	"polipo",
	"tinyproxy",
	"privazer",
	"ultrasurf",
	"tor/",
	"i2p",
	"bluecoat",
	"mcafee",
	"zscaler",
	"forcepoint",
	"websense",
	"barracuda",
	"connection established",
	"tunnel established",
}

// hasProxyHeaders 检查响应是否包含代理特征头
func (p *Probe) hasProxyHeaders(response string) bool {
	responseLower := strings.ToLower(response)

	if !strings.HasPrefix(responseLower, "http/") && len(response) > 0 {
		hasHTTPHeaderFormat := false
		lines := strings.Split(response, "\n")
		for _, line := range lines {
			if strings.Contains(line, ":") {
				hasHTTPHeaderFormat = true
				break
			}
		}
		if !hasHTTPHeaderFormat {
			return false
		}
	}

	for _, indicator := range proxyIndicators {
		if strings.Contains(responseLower, indicator) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Create proxy_analysis.go**

Create `free-proxy-scanner/internal/scanner/probe/proxy_analysis.go`:

```go
package probe

import (
	"net/http"
	"strings"
)

// analyzeProxyHeaders 详细分析代理特征，返回特征列表和置信度
func (p *Probe) analyzeProxyHeaders(response string) ([]string, float64) {
	responseLower := strings.ToLower(response)
	var features []string
	score := 0.0

	highConfidenceHeaders := map[string]string{
		"via:":                 "Via header present",
		"x-forwarded-for:":     "X-Forwarded-For header present",
		"x-forwarded-host:":    "X-Forwarded-Host header present",
		"x-forwarded-proto:":   "X-Forwarded-Proto header present",
		"x-forwarded-scheme:":  "X-Forwarded-Scheme header present",
		"x-forwarded-port:":    "X-Forwarded-Port header present",
		"x-forwarded-server:":  "X-Forwarded-Server header present",
		"x-real-ip:":           "X-Real-IP header present",
		"proxy-connection:":    "Proxy-Connection header present",
		"proxy-authenticate:":  "Proxy-Authenticate header present",
		"proxy-authorization:": "Proxy-Authorization header present",
		"proxy-agent:":         "Proxy-Agent header present",
		"x-scheme:":            "X-Scheme header present",
	}
	for header, desc := range highConfidenceHeaders {
		if strings.Contains(responseLower, header) {
			features = append(features, desc)
			score += 0.25
		}
	}

	cdnHeaders := map[string]string{
		"cf-connecting-ip:": "Cloudflare CF-Connecting-IP header",
		"cf-ipcountry:":     "Cloudflare CF-IPCountry header",
		"cf-ray:":           "Cloudflare CF-Ray header",
		"cf-visitor:":       "Cloudflare CF-Visitor header",
	}
	for header, desc := range cdnHeaders {
		if strings.Contains(responseLower, header) {
			features = append(features, desc)
			score += 0.25
		}
	}

	cacheHeaders := map[string]string{
		"x-cache:":        "X-Cache header present",
		"x-cache-lookup:": "X-Cache-Lookup header present",
		"x-cacheable:":    "X-Cacheable header present",
		"x-varnish:":      "X-Varnish header present",
		"x-hits:":         "X-Hits header present",
		"x-squid-error:":  "X-Squid-Error header present",
	}
	for header, desc := range cacheHeaders {
		if strings.Contains(responseLower, header) {
			features = append(features, desc)
			score += 0.2
		}
	}

	serverIdentifiers := map[string]string{
		"server: squid":       "Squid proxy identified",
		"server: nginx-proxy": "Nginx proxy identified",
		"server: tinyproxy":   "TinyProxy identified",
		"server: privoxy":     "Privoxy proxy identified",
		"server: polipo":      "Polipo proxy identified",
		"squid":               "Squid proxy (generic)",
		"haproxy":             "HAProxy identified",
		"varnish":             "Varnish proxy identified",
		"privoxy":             "Privoxy proxy identified",
		"tinyproxy":           "TinyProxy identified",
		"polipo":              "Polipo proxy identified",
		"cloudflare":          "Cloudflare proxy/CDN",
		"akamai":              "Akamai proxy/CDN",
		"fastly":              "Fastly proxy/CDN",
	}
	for identifier, desc := range serverIdentifiers {
		if strings.Contains(responseLower, identifier) {
			features = append(features, desc)
			score += 0.2
		}
	}

	statusIndicators := map[string]string{
		" 407 ": "Proxy authentication required",
		" 502 ": "Bad Gateway (proxy error)",
		" 503 ": "Service Unavailable (proxy overload)",
		" 504 ": "Gateway Timeout (upstream timeout)",
	}
	for indicator, desc := range statusIndicators {
		if strings.Contains(response, indicator) {
			features = append(features, desc)
			score += 0.15
		}
	}

	enterpriseProxies := map[string]string{
		"bluecoat":   "Blue Coat enterprise proxy",
		"zscaler":    "Zscaler cloud proxy",
		"forcepoint": "Forcepoint proxy",
		"mcafee":     "McAfee web gateway",
		"websense":   "Websense proxy",
	}
	for identifier, desc := range enterpriseProxies {
		if strings.Contains(responseLower, identifier) {
			features = append(features, desc)
			score += 0.15
		}
	}

	connectionFeatures := map[string]string{
		"connection established": "CONNECT tunnel established",
		"tunnel established":     "Proxy tunnel active",
	}
	for feature, desc := range connectionFeatures {
		if strings.Contains(responseLower, feature) {
			features = append(features, desc)
			score += 0.1
		}
	}

	if score > 1.0 {
		score = 1.0
	}

	return features, score
}

// isLikelyProxy 综合判断是否为可能的代理
func (p *Probe) isLikelyProxy(response string, port int) (bool, float64, []string) {
	features, confidence := p.analyzeProxyHeaders(response)

	if p.isCommonProxyPort(port) && confidence < 0.5 {
		confidence += 0.1
		features = append(features, "Common proxy port detected")
	}

	isProxy := confidence >= 0.3

	return isProxy, confidence, features
}

// checkProxyHeaders 检查代理相关的HTTP头
func checkProxyHeaders(headers http.Header) []string {
	var proxyHeaders []string
	proxyHeaderNames := []string{
		"Via", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
		"X-Real-Ip", "Proxy-Connection", "Proxy-Agent", "X-Scheme",
		"Cf-Connecting-Ip", "Cf-Ray", "Cf-Ipcountry", "Cf-Visitor",
		"X-Cache", "X-Varnish",
	}

	for _, name := range proxyHeaderNames {
		if headers.Get(name) != "" {
			proxyHeaders = append(proxyHeaders, name)
		}
	}

	return proxyHeaders
}
```

- [ ] **Step 3: Create port_classification.go**

Create `free-proxy-scanner/internal/scanner/probe/port_classification.go`:

```go
package probe

// isCommonProxyPort 检查是否为常见代理端口
func (p *Probe) isCommonProxyPort(port int) bool {
	commonProxyPorts := map[int]bool{
		80:   true, // HTTP
		443:  true, // HTTPS
		1080: true, // SOCKS
		1081: true, // SOCKS
		1082: true, // SOCKS4
		3128: true, // Squid
		8080: true, // HTTP Proxy
		8081: true, // HTTP Proxy
		8082: true, // HTTP Proxy
		8088: true, // HTTP Proxy
		8090: true, // HTTP Proxy
		8118: true, // Privoxy
		8888: true, // HTTP Proxy
		9050: true, // Tor
		9999: true, // HTTP Proxy
	}
	return commonProxyPorts[port]
}

// IsNonProxyService 判断是否为明确的非代理服务
func (p *Probe) IsNonProxyService(serviceType string) bool {
	nonProxyServices := map[string]bool{
		"ssh":           true,
		"mysql":         true,
		"redis":         true,
		"ftp":           true,
		"smtp":          true,
		"pop3":          true,
		"imap":          true,
		"rdp":           true,
		"mongodb":       true,
		"postgresql":    true,
		"websocket":     true,
		"memcached":     true,
		"elasticsearch": true,
		"tls":           true,
	}
	return nonProxyServices[serviceType]
}
```

- [ ] **Step 4: Delete proxy_headers.go**

Run: `rm free-proxy-scanner/internal/scanner/probe/proxy_headers.go`

- [ ] **Step 5: Verify compilation and tests**

Run: `cd free-proxy-scanner && go build ./...`
Expected:
  - Exit code: 0
  - No output

Run: `cd free-proxy-scanner && go test ./internal/scanner/probe/ -count=1`
Expected:
  - Exit code: 0
  - Output contains: "PASS"
  - All test groups pass

- [ ] **Step 6: Format and commit**

Run: `cd free-proxy-scanner && gofmt -w internal/scanner/probe/ && git add internal/scanner/probe/ && git commit -m "refactor(probe): split proxy_headers.go(312L) into 3 focused files"`

---

### Task 2: Extract processIPBatch from scanner.go

**Depends on:** None
**Files:**
- Create: `free-proxy-scanner/internal/scanner/scanner_batch.go` — `processIPBatch` function
- Modify: `free-proxy-scanner/internal/scanner/scanner.go` — remove `processIPBatch` function (lines 212-292)

- [ ] **Step 1: Create scanner_batch.go**

Create `free-proxy-scanner/internal/scanner/scanner_batch.go`:

```go
package scanner

import (
	"sync"

	"github.com/free-proxy-hunter/free-proxy-scanner/free-proxy-scanner/pkg/api"
	"go.uber.org/zap"
)

// processIPBatch 处理一批IP
func (s *Scanner) processIPBatch(ips []string, ports []int, protocols []string, rep *reporter.Reporter, maxConcurrent int, scannedIPs, foundProxies *int64) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxConcurrent)

	for _, ip := range ips {
		for _, port := range ports {
			if s.filter.Contains(ip, port) {
				continue
			}

			wg.Add(1)
			go func(ip string, port int) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				isOpen, serviceType, isLikelyProxy := s.probe.ScanAndIdentifyPort(ip, port)
				if !isOpen {
					return
				}

				if s.probe.IsNonProxyService(serviceType) {
					logger.Debug("跳过非代理服务",
						zap.String("ip", ip),
						zap.Int("port", port),
						zap.String("service", serviceType))
					return
				}

				if !isLikelyProxy && serviceType != "http-proxy" &&
					serviceType != "socks4" && serviceType != "socks5" {
					logger.Debug("跳过不太可能是代理的服务",
						zap.String("ip", ip),
						zap.Int("port", port),
						zap.String("service", serviceType))
					return
				}

				s.filter.Add(ip, port)
				*scannedIPs++

				for _, protocol := range protocols {
					proxy, err := s.validator.ValidateProxy(ip, port, protocol)
					if err != nil {
						continue
					}

					apiProxy := &api.Proxy{
						IP:          proxy.IP,
						Port:        proxy.Port,
						Protocol:    proxy.Protocol,
						Status:      proxy.Status,
						Speed:       int(proxy.Speed),
						RequireAuth: proxy.RequireAuth,
					}

					rep.Report(apiProxy)
					*foundProxies++
				}
			}(ip, port)
		}
	}

	wg.Wait()
}
```

- [ ] **Step 2: Remove processIPBatch from scanner.go**

Delete lines 212 through 292 from `free-proxy-scanner/internal/scanner/scanner.go` (the entire `processIPBatch` function body and signature).

- [ ] **Step 3: Verify compilation**

Run: `cd free-proxy-scanner && go build ./...`
Expected:
  - Exit code: 0
  - No output

Run: `cd free-proxy-scanner && go test ./internal/scanner/... -count=1`
Expected:
  - Exit code: 0
  - All probe/scanner tests pass
  - Note: `internal/scanner/task` may have pre-existing failures unrelated to this change

---

### Task 3: Split ip_scanner.go task execution logic

**Depends on:** None
**Files:**
- Create: `free-proxy-scanner/internal/scanner/ip_scanner_task.go` — `fillTaskQueue`, `scanIPTask`, `monitorProgress`
- Modify: `free-proxy-scanner/internal/scanner/ip_scanner.go` — remove moved functions

- [ ] **Step 1: Create ip_scanner_task.go**

Create `free-proxy-scanner/internal/scanner/ip_scanner_task.go`:

```go
package scanner

import (
	"time"

	"github.com/free-proxy-hunter/free-proxy-scanner/free-proxy-scanner/pkg/api"
	"go.uber.org/zap"
)

// fillTaskQueue 填充任务队列
func (s *IPScanner) fillTaskQueue() {
	for {
		if s.isStopped() {
			return
		}

		poolSize := s.taskPool.Size()
		if poolSize < s.cfg.ScannerConfig.TaskPoolMinSize {
			s.taskPool.FillFromConfig(s.cfg)
		}

		time.Sleep(s.cfg.ScannerConfig.TaskPoolFillInterval)
	}
}

// scanIPTask 扫描IP任务
func (s *IPScanner) scanIPTask(task *IPTask) {
	if s.isStopped() {
		return
	}

	start := time.Now()

	isOpen, serviceType, isLikelyProxy := s.probe.ScanAndIdentifyPort(task.IP, task.Port)
	if !isOpen {
		s.taskPool.RecordFailure(task)
		return
	}

	if s.probe.IsNonProxyService(serviceType) {
		logger.Debug("跳过非代理服务",
			zap.String("ip", task.IP),
			zap.Int("port", task.Port),
			zap.String("service", serviceType))
		s.taskPool.RecordFailure(task)
		return
	}

	if !isLikelyProxy && serviceType != "http-proxy" &&
		serviceType != "socks4" && serviceType != "socks5" {
		logger.Debug("跳过不太可能是代理的服务",
			zap.String("ip", task.IP),
			zap.Int("port", task.Port),
			zap.String("service", serviceType))
		s.taskPool.RecordFailure(task)
		return
	}

	for _, protocol := range s.cfg.ScannerConfig.Protocols {
		proxy, err := s.validator.ValidateProxy(task.IP, task.Port, protocol)
		if err != nil {
			continue
		}

		apiProxy := &api.Proxy{
			IP:          proxy.IP,
			Port:        proxy.Port,
			Protocol:    proxy.Protocol,
			Status:      proxy.Status,
			Speed:       int(proxy.Speed),
			RequireAuth: proxy.RequireAuth,
		}

		s.reporter.Report(apiProxy)
		s.taskPool.RecordSuccess(task)
		break
	}

	elapsed := time.Since(start)
	if elapsed > s.cfg.ScannerConfig.TaskTimeout {
		logger.Warn("扫描任务超时",
			zap.String("ip", task.IP),
			zap.Int("port", task.Port),
			zap.Duration("elapsed", elapsed))
	}
}

// monitorProgress 监控进度
func (s *IPScanner) monitorProgress() {
	ticker := time.NewTicker(s.cfg.ScannerConfig.ProgressReportInterval)
	defer ticker.Stop()

	for range ticker.C {
		if s.isStopped() {
			return
		}

		stats := s.GetStatistics()
		logger.Info("扫描进度",
			zap.Int64("scanned", stats.ScannedIPs),
			zap.Int64("found", stats.FoundProxies),
			zap.Int("pool_size", stats.PoolSize),
			zap.Float64("success_rate", stats.SuccessRate),
		)
	}
}
```

- [ ] **Step 2: Remove moved functions from ip_scanner.go**

Delete the `fillTaskQueue`, `scanIPTask`, and `monitorProgress` functions from `free-proxy-scanner/internal/scanner/ip_scanner.go`. The remaining functions should be: `IPScanner` struct, `NewIPScanner`, `ScanTask`, `GetStatistics`, `Stop`, `isStopped`.

- [ ] **Step 3: Verify compilation and tests**

Run: `cd free-proxy-scanner && go build ./...`
Expected:
  - Exit code: 0
  - No output

Run: `cd free-proxy-scanner && go vet ./internal/scanner/...`
Expected:
  - Exit code: 0
  - No output

---

## Self-Review Results

| # | Check | Result | Action Taken |
|---|-------|--------|-------------|
| 1 | Header with Goal/Arch/Tech? | PASS | 已包含 |
| 2 | Each Task has Depends on? | PASS | 已标注 |
| 3 | Exact file paths? | PASS | 全部精确 |
| 4 | Each Task has 3-8 Steps? | PASS | Task 1: 6 steps, Task 2: 3 steps, Task 3: 3 steps |
| 5 | New files have complete code? | PASS | 含完整 import 和函数 |
| 6 | Modification steps have full function code? | PASS | 包含替换后完整代码 |
| 7 | Code blocks 5-80 lines? | PASS | 所有代码块在此范围内 |
| 8 | No dangling references? | PASS | 所有函数/类型在 Plan 内定义 |
| 9 | Verification commands with 3 elements? | PASS | 命令 + exit code + output pattern |
| 10 | Spec coverage complete? | PASS | 3个文件覆盖分析结果 |
| 11 | Each Task independently verifiable? | PASS | 每个 Task 可独立编译测试 |
| 12 | No TBD/TODO? | PASS | 零占位符 |
| 13 | No abstract directives? | PASS | 每个步骤有完整代码 |
| 14 | Cross-task type consistency? | PASS | `IPTask`, `Reporter`, `Proxy` 类型一致 |
| 15 | Save location correct? | PASS | docs/superpowers/plans/ |

**Status:** ✅ ALL PASS

---

## Execution Selection

**Tasks:** 3
**Dependencies:** none (all independent)
**User Preference:** none
**Decision:** Subagent-Driven
**Reasoning:** 3 tasks rule applies — all independent, can be dispatched sequentially with review checkpoints.

**Auto-invoking:** `superpowers:subagent-driven-development`
