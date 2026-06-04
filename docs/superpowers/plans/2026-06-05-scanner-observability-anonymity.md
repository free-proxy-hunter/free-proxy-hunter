# Scanner Observability & Anonymity Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 将匿名等级分类集成到扫描流水线，创建可观测度量体系（Metrics + Heartbeat 丰富），让管理端实时掌握扫描器状态和代理质量分布。

**Architecture:** 扫描流水线中 validateHTTPProxyViaAbsoluteURI 已经读取了代理响应头 → 在返回响应时调用 ClassifyAnonymity() 分类匿名等级 → 填入 Proxy.AnonymityLevel → 上报时携带 anonymity 字段。同时创建 ScannerMetrics 收集结构化度量（端口扫描数/验证数/各协议数/各匿名等级数/延迟分布），通过现有 Heartbeat 机制上报聚合统计数据，避免新增 API 端点。

**Tech Stack:** Go 1.22, sync/atomic (计数器), time (延迟采样), resty/v2 (HTTP客户端)

**Risks:**
- Task 1 修改 validateHTTPProxyViaAbsoluteURI 返回签名，影响所有调用方 → 缓解：只扩展返回值，不改原有布尔逻辑
- Task 3 修改 HeartbeatRequest 结构，需确保服务端兼容 → 缓解：只添加新字段，不删除旧字段，服务端忽略未知字段
- Task 4 修改 scanner_batch.go 和 ip_scanner_task.go 两个路径 → 缓解：两个文件的改动模式一致，复制即可

---

### Task 1: 集成匿名等级分类到 Validator

**Depends on:** None
**Files:**
- Modify: `free-proxy-scanner/internal/scanner/validator/validator.go:71-128`（validateHTTPProxy 方法）
- Modify: `free-proxy-scanner/internal/scanner/validator/validator.go:319-370`（validateHTTPProxyViaAbsoluteURI 方法签名和返回值）
- Test: `free-proxy-scanner/internal/scanner/validator/anonymity_test.go`

- [ ] **Step 1: 修改 validateHTTPProxyViaAbsoluteURI 返回代理响应文本 — 用于匿名分类**

修改 `validator.go` 中 `validateHTTPProxyViaAbsoluteURI` 函数签名，从返回 `(bool, bool)` 改为返回 `(bool, bool, string)`，第三个返回值为代理响应文本。

文件: `free-proxy-scanner/internal/scanner/validator/validator.go:319`

```go
func (v *Validator) validateHTTPProxyViaAbsoluteURI(ip string, port int) (bool, bool, string) {
	address := net.JoinHostPort(ip, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", address, v.timeout)
	if err != nil {
		return false, false, ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(v.timeout))

	uriReq := "GET http://www.example.com/ HTTP/1.1\r\n" +
		"Host: www.example.com\r\n" +
		"Connection: close\r\n" +
		"\r\n"

	_, err = conn.Write([]byte(uriReq))
	if err != nil {
		return false, false, ""
	}

	buffer := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buffer = append(buffer, tmp[:n]...)
		}
		if err != nil || len(buffer) >= 4096 {
			break
		}
		if len(buffer) > 200 && strings.Contains(string(buffer), "\r\n\r\n") {
			break
		}
	}
	if len(buffer) == 0 {
		return false, false, ""
	}

	response := string(buffer)
	responseLower := strings.ToLower(response)

	if !strings.HasPrefix(response, "HTTP/") {
		return false, false, response
	}

	// 404/405 是普通Web服务器的响应
	if strings.Contains(response, " 404 ") || strings.Contains(response, " 405 ") {
		return false, false, response
	}

	// 407 = 需认证的代理
	if strings.Contains(response, " 407 ") {
		return true, true, response
	}

	// 200 响应 + 包含目标网站内容 = 代理转发成功
	if strings.Contains(response, " 200 ") {
		if strings.Contains(responseLower, "example domain") ||
			strings.Contains(responseLower, "example.com") ||
			strings.Contains(responseLower, "ietf") {
			return true, false, response
		}

		if strings.Contains(responseLower, "via:") ||
			strings.Contains(responseLower, "x-forwarded-") ||
			strings.Contains(responseLower, "proxy-") {
			return true, false, response
		}

		if strings.Contains(responseLower, "server:") {
			knownWebServers := []string{"nginx", "apache", "iis", "caddy", "goat", "cloudflare",
				"litespeed", "tomcat", "jetty", "openresty", "express", "lighttpd"}
			for _, ws := range knownWebServers {
				if strings.Contains(responseLower, ws) {
					return false, false, response
				}
			}
		}

		return false, false, response
	}

	// 3xx 重定向
	if strings.Contains(response, " 301 ") || strings.Contains(response, " 302 ") {
		return false, false, response
	}

	return false, false, response
}
```

- [ ] **Step 2: 修改 validateHTTPProxyViaCONNECT 返回代理响应文本**

修改 `validator.go` 中 `validateHTTPProxyViaCONNECT` 函数签名，从返回 `(bool, bool)` 改为返回 `(bool, bool, string)`。

文件: `free-proxy-scanner/internal/scanner/validator/validator.go:132`

```go
func (v *Validator) validateHTTPProxyViaCONNECT(ip string, port int) (bool, bool, string) {
	address := net.JoinHostPort(ip, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", address, v.timeout)
	if err != nil {
		return false, false, ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(v.timeout))

	connectReq := "CONNECT www.google.com:443 HTTP/1.1\r\n" +
		"Host: www.google.com:443\r\n" +
		"\r\n"

	_, err = conn.Write([]byte(connectReq))
	if err != nil {
		return false, false, ""
	}

	buffer := make([]byte, 0, 2048)
	tmp := make([]byte, 1024)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buffer = append(buffer, tmp[:n]...)
		}
		if err != nil || len(buffer) >= 2048 {
			break
		}
		if len(buffer) > 50 && strings.Contains(string(buffer), "\r\n\r\n") {
			break
		}
	}
	if len(buffer) == 0 {
		return false, false, ""
	}

	response := string(buffer)
	responseLower := strings.ToLower(response)

	if !strings.HasPrefix(response, "HTTP/") {
		return false, false, response
	}

	if strings.Contains(response, " 101 ") {
		return false, false, response
	}

	if strings.Contains(response, " 200 ") {
		if strings.Contains(responseLower, "connection established") ||
			strings.Contains(responseLower, "tunnel") {
			return true, false, response
		}

		// CONNECT 隧道模式：200 + 无代理特征头 = elite
		// 这里无法从 CONNECT 响应判断匿名等级，因为隧道不暴露原始请求头
		// 默认标记为 anonymous（CONNECT 本身会隐藏客户端 IP）
		return true, false, response
	}

	// 407 = 需认证
	if strings.Contains(response, " 407 ") {
		return true, true, response
	}

	return false, false, response
}
```

注意：CONNECT 隧道的 CONNECT 响应头不包含 X-Forwarded-For 等信息，因此 CONNECT 代理默认分类为 anonymous。真正精确的匿名分类只能在 AbsoluteURI 模式的响应中完成。

- [ ] **Step 3: 修改 validateHTTPProxy 调用 ClassifyAnonymity — 在验证成功后分类匿名等级**

文件: `free-proxy-scanner/internal/scanner/validator/validator.go:71-128`（替换整个 validateHTTPProxy 方法）

```go
func (v *Validator) validateHTTPProxy(ip string, port int, protocol string) (*Proxy, error) {
	startTime := time.Now()

	// 1. 首先尝试 CONNECT 方法验证
	isProxy, needsAuth, connectResponse := v.validateHTTPProxyViaCONNECT(ip, port)

	if isProxy {
		if !needsAuth && !v.skipIPVerify && v.ipVerifier != nil && v.ipVerifier.ScannerIP() != "" {
			proxyAddr := net.JoinHostPort(ip, strconv.Itoa(port))
			egressIP, ipChanged := v.ipVerifier.VerifyProxyHTTP(proxyAddr, protocol)
			if !ipChanged {
				return nil, fmt.Errorf("IP验证失败：出口IP(%s)与扫描器IP相同，流量未经过代理转发", egressIP)
			}
		}

		duration := time.Since(startTime).Milliseconds()
		status := "available"
		if needsAuth {
			status = "auth_required"
		}

		// CONNECT 隧道模式下分类匿名等级
		// CONNECT 代理默认为 anonymous（隧道隐藏客户端IP，但代理可能添加 Via 头）
		anonymityLevel := AnonymityAnonymous
		if connectResponse != "" {
			anonInfo := ClassifyAnonymity(connectResponse, v.scannerIP)
			if anonInfo.Level != AnonymityUnknown {
				anonymityLevel = anonInfo.Level
			}
		}
		// CONNECT 隧道如果 IP 验证通过（出口IP != 扫描器IP），则至少是 anonymous
		// 如果隧道响应没有任何代理特征头，升级为 elite
		if anonymityLevel == AnonymityAnonymous {
			responseLower := strings.ToLower(connectResponse)
			if !strings.Contains(responseLower, "via:") &&
				!strings.Contains(responseLower, "proxy-agent:") &&
				!strings.Contains(responseLower, "x-proxy-id:") {
				anonymityLevel = AnonymityElite
			}
		}

		return &Proxy{
			IP:             ip,
			Port:           port,
			Protocol:       protocol,
			Status:         status,
			Speed:          duration,
			RequireAuth:    needsAuth,
			AnonymityLevel: anonymityLevel,
		}, nil
	}

	// 2. CONNECT 失败，尝试绝对 URI 方式验证
	isProxyURI, needsAuthURI, uriResponse := v.validateHTTPProxyViaAbsoluteURI(ip, port)

	if isProxyURI {
		if !needsAuthURI && !v.skipIPVerify && v.ipVerifier != nil && v.ipVerifier.ScannerIP() != "" {
			proxyAddr := net.JoinHostPort(ip, strconv.Itoa(port))
			egressIP, ipChanged := v.ipVerifier.VerifyProxyHTTP(proxyAddr, "http")
			if !ipChanged {
				return nil, fmt.Errorf("IP验证失败：出口IP(%s)与扫描器IP相同，流量未经过代理转发", egressIP)
			}
		}

		duration := time.Since(startTime).Milliseconds()
		status := "available"
		if needsAuthURI {
			status = "auth_required"
		}

		// 绝对 URI 模式下分类匿名等级
		anonymityLevel := AnonymityUnknown
		if uriResponse != "" {
			anonInfo := ClassifyAnonymity(uriResponse, v.scannerIP)
			anonymityLevel = anonInfo.Level
		}

		return &Proxy{
			IP:             ip,
			Port:           port,
			Protocol:       "http",
			Status:         status,
			Speed:          duration,
			RequireAuth:    needsAuthURI,
			AnonymityLevel: anonymityLevel,
		}, nil
	}

	return nil, fmt.Errorf("CONNECT和绝对URI验证均失败，不是有效的HTTP代理")
}
```

- [ ] **Step 4: 添加 scannerIP 字段到 Validator 以支持匿名等级分类**

文件: `free-proxy-scanner/internal/scanner/validator/validator.go:24-30`（替换 Validator 结构体定义）

```go
type Validator struct {
	timeout       time.Duration
	testURLs      []string
	scannerIP     string
	skipIPVerify  bool
	ipVerifier    *IPVerifier
}
```

无需修改 — `scannerIP` 字段已存在。

- [ ] **Step 5: 修复所有调用 validateHTTPProxyViaCONNECT 和 validateHTTPProxyViaAbsoluteURI 的测试文件**

所有测试文件中调用这两个方法的地方需要适配新的返回值签名。将 `v.validateHTTPProxyViaCONNECT(ip, port)` 改为 `isProxy, needsAuth, _ := v.validateHTTPProxyViaCONNECT(ip, port)`，将 `v.validateHTTPProxyViaAbsoluteURI(ip, port)` 改为 `isProxy, needsAuth, _ := v.validateHTTPProxyViaAbsoluteURI(ip, port)`。

- [ ] **Step 6: 验证匿名等级集成**
Run: `cd free-proxy-scanner && go build ./...`
Expected:
  - Exit code: 0
  - Output does NOT contain: "undefined" or "cannot use"

- [ ] **Step 7: 提交**
Run: `cd free-proxy-scanner && git add -A && git commit -m "feat(validator): integrate anonymity classification into HTTP proxy validation pipeline

- Extend validateHTTPProxyViaCONNECT and validateHTTPProxyViaAbsoluteURI to return response text
- Call ClassifyAnonymity() on proxy responses to determine anonymity level
- Populate Proxy.AnonymityLevel field (transparent/anonymous/elite)
- CONNECT proxies default to anonymous, upgraded to elite if no proxy headers detected
- AbsoluteURI proxies classified based on X-Forwarded-For, Via, Proxy-Agent headers

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`

---

### Task 2: 创建 ScannerMetrics 度量收集器

**Depends on:** None
**Files:**
- Create: `free-proxy-scanner/internal/scanner/metrics/metrics.go`
- Create: `free-proxy-scanner/internal/scanner/metrics/metrics_test.go`

- [ ] **Step 1: 创建 ScannerMetrics — 结构化度量收集器**

```go
package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// ScannerMetrics 收集扫描器运行时度量数据
// 使用 atomic 操作保证并发安全，无需加锁
type ScannerMetrics struct {
	// 计数器
	portsScanned      atomic.Int64 // 扫描的端口总数
	portsOpen         atomic.Int64 // 开放的端口数
	proxiesValidated  atomic.Int64 // 验证成功的代理数
	proxiesPostValid  atomic.Int64 // 二次校验通过的代理数
	proxiesFailed     atomic.Int64 // 验证失败的代理数
	ipsScanned        atomic.Int64 // 扫描的 IP 总数
	tasksCompleted    atomic.Int64 // 完成的任务数
	tasksFailed       atomic.Int64 // 失败的任务数
	apiReportsSuccess atomic.Int64 // API 上报成功次数
	apiReportsFailed  atomic.Int64 // API 上报失败次数

	// 按协议分类
	httpProxies  atomic.Int64
	socks4Proxies atomic.Int64
	socks5Proxies atomic.Int64

	// 按匿名等级分类
	transparentProxies atomic.Int64
	anonymousProxies   atomic.Int64
	eliteProxies       atomic.Int64
	unknownAnonProxies atomic.Int64

	// 延迟采样（最近 N 个采样的滑动窗口）
	latencyMu    sync.Mutex
	latencies    []int64 // 毫秒
	latencyIndex int
	latencySize  int

	// 启动时间
	startTime time.Time
}

// NewScannerMetrics 创建度量收集器
func NewScannerMetrics() *ScannerMetrics {
	return &ScannerMetrics{
		latencies:  make([]int64, 1000), // 保留最近 1000 个延迟采样
		latencySize: 1000,
		startTime:  time.Now(),
	}
}

// IncrPortsScanned 增加扫描端口计数
func (m *ScannerMetrics) IncrPortsScanned() { m.portsScanned.Add(1) }

// IncrPortsOpen 增加开放端口计数
func (m *ScannerMetrics) IncrPortsOpen() { m.portsOpen.Add(1) }

// IncrProxiesValidated 增加验证成功代理计数
func (m *ScannerMetrics) IncrProxiesValidated() { m.proxiesValidated.Add(1) }

// IncrProxiesPostValid 增加二次校验通过代理计数
func (m *ScannerMetrics) IncrProxiesPostValid() { m.proxiesPostValid.Add(1) }

// IncrProxiesFailed 增加验证失败代理计数
func (m *ScannerMetrics) IncrProxiesFailed() { m.proxiesFailed.Add(1) }

// IncrIPsScanned 增加扫描IP计数
func (m *ScannerMetrics) IncrIPsScanned() { m.ipsScanned.Add(1) }

// IncrTasksCompleted 增加完成任务计数
func (m *ScannerMetrics) IncrTasksCompleted() { m.tasksCompleted.Add(1) }

// IncrTasksFailed 增加失败任务计数
func (m *ScannerMetrics) IncrTasksFailed() { m.tasksFailed.Add(1) }

// IncrAPIReportsSuccess 增加API上报成功计数
func (m *ScannerMetrics) IncrAPIReportsSuccess() { m.apiReportsSuccess.Add(1) }

// IncrAPIReportsFailed 增加API上报失败计数
func (m *ScannerMetrics) IncrAPIReportsFailed() { m.apiReportsFailed.Add(1) }

// IncrProxiesByProtocol 按协议类型增加代理计数
func (m *ScannerMetrics) IncrProxiesByProtocol(protocol string) {
	switch protocol {
	case "http", "https", "http-proxy":
		m.httpProxies.Add(1)
	case "socks4":
		m.socks4Proxies.Add(1)
	case "socks5":
		m.socks5Proxies.Add(1)
	}
}

// IncrProxiesByAnonymity 按匿名等级增加代理计数
func (m *ScannerMetrics) IncrProxiesByAnonymity(anonymity string) {
	switch anonymity {
	case "transparent":
		m.transparentProxies.Add(1)
	case "anonymous":
		m.anonymousProxies.Add(1)
	case "elite":
		m.eliteProxies.Add(1)
	default:
		m.unknownAnonProxies.Add(1)
	}
}

// RecordLatency 记录验证延迟（毫秒）
func (m *ScannerMetrics) RecordLatency(ms int64) {
	m.latencyMu.Lock()
	m.latencies[m.latencyIndex] = ms
	m.latencyIndex = (m.latencyIndex + 1) % m.latencySize
	m.latencyMu.Unlock()
}

// Snapshot 返回当前度量快照
func (m *ScannerMetrics) Snapshot() *MetricsSnapshot {
	s := &MetricsSnapshot{
		UptimeSeconds:       int64(time.Since(m.startTime).Seconds()),
		PortsScanned:        m.portsScanned.Load(),
		PortsOpen:           m.portsOpen.Load(),
		ProxiesValidated:    m.proxiesValidated.Load(),
		ProxiesPostValid:    m.proxiesPostValid.Load(),
		ProxiesFailed:       m.proxiesFailed.Load(),
		IPsScanned:          m.ipsScanned.Load(),
		TasksCompleted:      m.tasksCompleted.Load(),
		TasksFailed:         m.tasksFailed.Load(),
		APIReportsSuccess:   m.apiReportsSuccess.Load(),
		APIReportsFailed:    m.apiReportsFailed.Load(),
		HTTPProxies:         m.httpProxies.Load(),
		SOCKS4Proxies:       m.socks4Proxies.Load(),
		SOCKS5Proxies:       m.socks5Proxies.Load(),
		TransparentProxies:  m.transparentProxies.Load(),
		AnonymousProxies:    m.anonymousProxies.Load(),
		EliteProxies:        m.eliteProxies.Load(),
		UnknownAnonProxies:  m.unknownAnonProxies.Load(),
	}

	// 计算延迟统计
	m.latencyMu.Lock()
	validLatencies := make([]int64, 0, m.latencySize)
	for i := 0; i < m.latencySize; i++ {
		if m.latencies[i] > 0 {
			validLatencies = append(validLatencies, m.latencies[i])
		}
	}
	m.latencyMu.Unlock()

	if len(validLatencies) > 0 {
		s.AvgLatencyMs = avgInt64(validLatencies)
		s.MaxLatencyMs = maxInt64(validLatencies)
		s.MinLatencyMs = minInt64(validLatencies)
		s.P50LatencyMs = percentileInt64(validLatencies, 50)
		s.P95LatencyMs = percentileInt64(validLatencies, 95)
		s.P99LatencyMs = percentileInt64(validLatencies, 99)
	}

	return s
}

// MetricsSnapshot 度量快照（不可变，用于上报和展示）
type MetricsSnapshot struct {
	UptimeSeconds      int64 `json:"uptime_seconds"`
	PortsScanned       int64 `json:"ports_scanned"`
	PortsOpen          int64 `json:"ports_open"`
	ProxiesValidated   int64 `json:"proxies_validated"`
	ProxiesPostValid   int64 `json:"proxies_post_valid"`
	ProxiesFailed      int64 `json:"proxies_failed"`
	IPsScanned         int64 `json:"ips_scanned"`
	TasksCompleted     int64 `json:"tasks_completed"`
	TasksFailed        int64 `json:"tasks_failed"`
	APIReportsSuccess  int64 `json:"api_reports_success"`
	APIReportsFailed   int64 `json:"api_reports_failed"`
	HTTPProxies        int64 `json:"http_proxies"`
	SOCKS4Proxies      int64 `json:"socks4_proxies"`
	SOCKS5Proxies      int64 `json:"socks5_proxies"`
	TransparentProxies int64 `json:"transparent_proxies"`
	AnonymousProxies   int64 `json:"anonymous_proxies"`
	EliteProxies       int64 `json:"elite_proxies"`
	UnknownAnonProxies int64 `json:"unknown_anon_proxies"`
	AvgLatencyMs       int64 `json:"avg_latency_ms"`
	MaxLatencyMs       int64 `json:"max_latency_ms"`
	MinLatencyMs       int64 `json:"min_latency_ms"`
	P50LatencyMs       int64 `json:"p50_latency_ms"`
	P95LatencyMs       int64 `json:"p95_latency_ms"`
	P99LatencyMs       int64 `json:"p99_latency_ms"`
}

// 辅助函数
func avgInt64(vals []int64) int64 {
	var sum int64
	for _, v := range vals {
		sum += v
	}
	return sum / int64(len(vals))
}

func maxInt64(vals []int64) int64 {
	m := vals[0]
	for _, v := range vals[1:] {
		if v > m {
			m = v
		}
	}
	return m
}

func minInt64(vals []int64) int64 {
	m := vals[0]
	for _, v := range vals[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

func percentileInt64(sorted []int64, p int) int64 {
	// 简单排序后取百分位
	n := len(sorted)
	if n == 0 {
		return 0
	}
	// 简单选择排序（数据量 <= 1000，足够快）
	s := make([]int64, n)
	copy(s, sorted)
	for i := 0; i < n-1; i++ {
		for j := i + 1; j < n; j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
	idx := (p * n) / 100
	if idx >= n {
		idx = n - 1
	}
	return s[idx]
}
```

- [ ] **Step 2: 创建 ScannerMetrics 单元测试**

```go
package metrics

import (
	"sync"
	"testing"
)

func TestScannerMetrics_ConcurrentIncrements(t *testing.T) {
	m := NewScannerMetrics()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.IncrPortsScanned()
			m.IncrProxiesValidated()
			m.IncrProxiesByProtocol("http")
			m.IncrProxiesByAnonymity("elite")
			m.RecordLatency(int64(i))
		}()
	}
	wg.Wait()

	snap := m.Snapshot()
	if snap.PortsScanned != 100 {
		t.Errorf("expected PortsScanned=100, got %d", snap.PortsScanned)
	}
	if snap.ProxiesValidated != 100 {
		t.Errorf("expected ProxiesValidated=100, got %d", snap.ProxiesValidated)
	}
	if snap.HTTPProxies != 100 {
		t.Errorf("expected HTTPProxies=100, got %d", snap.HTTPProxies)
	}
	if snap.EliteProxies != 100 {
		t.Errorf("expected EliteProxies=100, got %d", snap.EliteProxies)
	}
}

func TestScannerMetrics_ProtocolClassification(t *testing.T) {
	m := NewScannerMetrics()
	m.IncrProxiesByProtocol("http")
	m.IncrProxiesByProtocol("https")
	m.IncrProxiesByProtocol("socks4")
	m.IncrProxiesByProtocol("socks5")
	m.IncrProxiesByProtocol("unknown")

	snap := m.Snapshot()
	if snap.HTTPProxies != 2 {
		t.Errorf("expected HTTPProxies=2, got %d", snap.HTTPProxies)
	}
	if snap.SOCKS4Proxies != 1 {
		t.Errorf("expected SOCKS4Proxies=1, got %d", snap.SOCKS4Proxies)
	}
	if snap.SOCKS5Proxies != 1 {
		t.Errorf("expected SOCKS5Proxies=1, got %d", snap.SOCKS5Proxies)
	}
}

func TestScannerMetrics_AnonymityClassification(t *testing.T) {
	m := NewScannerMetrics()
	m.IncrProxiesByAnonymity("transparent")
	m.IncrProxiesByAnonymity("anonymous")
	m.IncrProxiesByAnonymity("elite")
	m.IncrProxiesByAnonymity("unknown")

	snap := m.Snapshot()
	if snap.TransparentProxies != 1 {
		t.Errorf("expected TransparentProxies=1, got %d", snap.TransparentProxies)
	}
	if snap.AnonymousProxies != 1 {
		t.Errorf("expected AnonymousProxies=1, got %d", snap.AnonymousProxies)
	}
	if snap.EliteProxies != 1 {
		t.Errorf("expected EliteProxies=1, got %d", snap.EliteProxies)
	}
	if snap.UnknownAnonProxies != 1 {
		t.Errorf("expected UnknownAnonProxies=1, got %d", snap.UnknownAnonProxies)
	}
}

func TestScannerMetrics_LatencyStats(t *testing.T) {
	m := NewScannerMetrics()
	for _, l := range []int64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100} {
		m.RecordLatency(l)
	}

	snap := m.Snapshot()
	if snap.MinLatencyMs != 10 {
		t.Errorf("expected MinLatencyMs=10, got %d", snap.MinLatencyMs)
	}
	if snap.MaxLatencyMs != 100 {
		t.Errorf("expected MaxLatencyMs=100, got %d", snap.MaxLatencyMs)
	}
	if snap.AvgLatencyMs != 55 {
		t.Errorf("expected AvgLatencyMs=55, got %d", snap.AvgLatencyMs)
	}
	if snap.UptimeSeconds < 0 {
		t.Errorf("UptimeSeconds should be non-negative, got %d", snap.UptimeSeconds)
	}
}

func TestScannerMetrics_EmptyLatency(t *testing.T) {
	m := NewScannerMetrics()
	snap := m.Snapshot()
	if snap.AvgLatencyMs != 0 {
		t.Errorf("expected AvgLatencyMs=0 for empty, got %d", snap.AvgLatencyMs)
	}
}
```

- [ ] **Step 3: 验证 ScannerMetrics**
Run: `cd free-proxy-scanner && go test ./internal/scanner/metrics/ -v -count=1`
Expected:
  - Exit code: 0
  - Output contains: "PASS"
  - Output does NOT contain: "FAIL"

- [ ] **Step 4: 提交**
Run: `cd free-proxy-scanner && git add -A && git commit -m "feat(metrics): create ScannerMetrics with concurrent-safe counters and latency tracking

- Atomic counters for ports/proxies/tasks/API reports
- Per-protocol breakdown (HTTP/SOCKS4/SOCKS5)
- Per-anonymity breakdown (transparent/anonymous/elite/unknown)
- Sliding window latency stats (avg/min/max/p50/p95/p99)
- MetricsSnapshot for immutable reporting

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`

---

### Task 3: 丰富 Heartbeat 上报真实度量数据

**Depends on:** Task 2
**Files:**
- Modify: `free-proxy-scanner/pkg/api/client.go:147-154`（HeartbeatRequest 结构体）
- Modify: `free-proxy-scanner/cmd/scanner/cmd/scan.go:205-228`（heartbeatLoop 函数）
- Modify: `free-proxy-scanner/internal/scanner/reporter/reporter.go`（添加 Metrics 引用）

- [ ] **Step 1: 扩展 HeartbeatRequest 携带度量数据**

文件: `free-proxy-scanner/pkg/api/client.go:147-154`（替换 HeartbeatRequest 结构体）

```go
// HeartbeatRequest 心跳请求
type HeartbeatRequest struct {
	ScannerID      string  `json:"scanner_id"`
	Status         string  `json:"status"`
	TaskCount      int     `json:"task_count"`
	CPUUsage       float64 `json:"cpu_usage"`
	MemoryUsage    float64 `json:"memory_usage"`
	NetworkTraffic int64   `json:"network_traffic"`
	// 度量数据 — 扫描器运行时统计
	PortsScanned       int64 `json:"ports_scanned"`
	ProxiesValidated   int64 `json:"proxies_validated"`
	ProxiesPostValid   int64 `json:"proxies_post_valid"`
	ProxiesFailed      int64 `json:"proxies_failed"`
	IPsScanned         int64 `json:"ips_scanned"`
	TasksCompleted     int64 `json:"tasks_completed"`
	HTTPProxies        int64 `json:"http_proxies"`
	SOCKS4Proxies      int64 `json:"socks4_proxies"`
	SOCKS5Proxies      int64 `json:"socks5_proxies"`
	TransparentProxies int64 `json:"transparent_proxies"`
	AnonymousProxies   int64 `json:"anonymous_proxies"`
	EliteProxies       int64 `json:"elite_proxies"`
	AvgLatencyMs       int64 `json:"avg_latency_ms"`
	P95LatencyMs       int64 `json:"p95_latency_ms"`
	UptimeSeconds      int64 `json:"uptime_seconds"`
}
```

- [ ] **Step 2: 修改 Reporter 持有 Metrics 引用并记录上报成功/失败**

文件: `free-proxy-scanner/internal/scanner/reporter/reporter.go`

在 Reporter 结构体中添加 metrics 字段，并在 reportWithRetry 中记录成功/失败：

```go
// 在 Reporter 结构体中添加字段
type Reporter struct {
	apiClient  *api.Client
	cfg        config.ReportConfig
	taskID     uint
	buffer     []*api.Proxy
	bufferMu   sync.Mutex
	stopCh     chan struct{}
	flushDone  chan struct{}
	metrics    *metrics.ScannerMetrics // 新增
}

// 修改 NewReporter 接受 metrics 参数
func NewReporter(apiClient *api.Client, cfg config.ReportConfig, taskID uint, m *metrics.ScannerMetrics) *Reporter {
	r := &Reporter{
		apiClient: apiClient,
		cfg:       cfg,
		taskID:    taskID,
		buffer:    make([]*api.Proxy, 0, cfg.BatchSize),
		stopCh:    make(chan struct{}),
		flushDone: make(chan struct{}),
		metrics:   m,
	}
	go r.flushLoop()
	return r
}

// 在 reportWithRetry 成功/失败处添加计数
// 成功时：r.metrics.IncrAPIReportsSuccess()
// 失败时：r.metrics.IncrAPIReportsFailed()
```

- [ ] **Step 3: 修改 heartbeatLoop 从 Metrics 获取真实数据**

文件: `free-proxy-scanner/cmd/scanner/cmd/scan.go:205-228`（替换 heartbeatLoop 函数）

需要将 `*metrics.ScannerMetrics` 传递到 heartbeatLoop，并在每次心跳时获取 Snapshot 填充 HeartbeatRequest。

```go
// heartbeatLoop 心跳循环 — 携带度量数据
func heartbeatLoop(ctx context.Context, client *api.Client, cfg *config.Config, m *metrics.ScannerMetrics) {
	ticker := time.NewTicker(cfg.Task.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			req := &api.HeartbeatRequest{
				ScannerID:    cfg.Scanner.ID,
				Status:       "online",
			}

			// 从 Metrics 获取真实度量数据
			if m != nil {
				snap := m.Snapshot()
				req.PortsScanned = snap.PortsScanned
				req.ProxiesValidated = snap.ProxiesValidated
				req.ProxiesPostValid = snap.ProxiesPostValid
				req.ProxiesFailed = snap.ProxiesFailed
				req.IPsScanned = snap.IPsScanned
				req.TasksCompleted = snap.TasksCompleted
				req.HTTPProxies = snap.HTTPProxies
				req.SOCKS4Proxies = snap.SOCKS4Proxies
				req.SOCKS5Proxies = snap.SOCKS5Proxies
				req.TransparentProxies = snap.TransparentProxies
				req.AnonymousProxies = snap.AnonymousProxies
				req.EliteProxies = snap.EliteProxies
				req.AvgLatencyMs = snap.AvgLatencyMs
				req.P95LatencyMs = snap.P95LatencyMs
				req.UptimeSeconds = snap.UptimeSeconds
			}

			if err := client.Heartbeat(req); err != nil {
				logger.Error(fmt.Sprintf("发送心跳失败: %v", err))
			}
		}
	}
}
```

- [ ] **Step 4: 验证 Heartbeat 丰富**
Run: `cd free-proxy-scanner && go build ./...`
Expected:
  - Exit code: 0
  - Output does NOT contain: "undefined" or "not enough arguments"

- [ ] **Step 5: 提交**
Run: `cd free-proxy-scanner && git add -A && git commit -m "feat(heartbeat): enrich heartbeat with real scanner metrics data

- Extend HeartbeatRequest with proxy/protocol/anonymity/latency stats
- Modify Reporter to hold Metrics reference for API report counting
- Pass ScannerMetrics to heartbeatLoop for real-time metric reporting
- Remove hardcoded zero values for CPU/Memory/Network (to be filled by system stats later)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`

---

### Task 4: 将 Metrics 和 Anonymity 串联到扫描流水线

**Depends on:** Task 1, Task 2, Task 3
**Files:**
- Modify: `free-proxy-scanner/internal/scanner/scanner.go`（添加 metrics 字段）
- Modify: `free-proxy-scanner/internal/scanner/scanner_batch.go`（添加 metrics 埋点）
- Modify: `free-proxy-scanner/internal/scanner/ip_scanner_task.go`（添加 metrics 埋点 + anonymity 字段）
- Modify: `free-proxy-scanner/cmd/scanner/cmd/scan.go`（创建 Metrics 实例并注入）

- [ ] **Step 1: 在 Scanner 中添加 Metrics 字段**

文件: `free-proxy-scanner/internal/scanner/scanner.go:20-28`

```go
type Scanner struct {
	cfg           *config.Config
	apiClient     *api.Client
	probe         *probe.Probe
	validator     *validator.Validator
	postValidator *validator.PostValidator
	metrics       *metrics.ScannerMetrics
	filter        *filter.BloomFilter
	workerPool    chan struct{}
}
```

修改 NewScanner 创建并注入 Metrics：

```go
func NewScanner(cfg *config.Config, apiClient *api.Client) *Scanner {
	m := metrics.NewScannerMetrics()
	return &Scanner{
		cfg:           cfg,
		apiClient:     apiClient,
		probe:         probe.NewProbe(cfg.Scan.PortScanTimeout),
		validator:     validator.NewValidator(cfg.Scan.ProxyTestTimeout, cfg.Scan.TestURL),
		postValidator: validator.NewPostValidator(cfg.Scan.ProxyTestTimeout),
		metrics:       m,
		filter:        filter.NewBloomFilter(cfg.Filter.BloomSize, cfg.Filter.BloomFPRate, cfg.Filter.SegmentTTL),
		workerPool:    make(chan struct{}, cfg.Scanner.Concurrency),
	}
}

// GetMetrics 返回 Metrics 实例（供外部读取）
func (s *Scanner) GetMetrics() *metrics.ScannerMetrics {
	return s.metrics
}
```

- [ ] **Step 2: 在 scanner_batch.go 添加 metrics 埋点 — 记录每个扫描阶段的度量**

文件: `free-proxy-scanner/internal/scanner/scanner_batch.go`

在 processIPBatch 中，每个关键阶段添加 metrics 记录：

```go
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

				// 记录端口扫描
				s.metrics.IncrPortsScanned()

				isOpen, serviceType, isLikelyProxy := s.probe.ScanAndIdentifyPort(ip, port)
				if !isOpen {
					return
				}

				s.metrics.IncrPortsOpen()

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
				atomic.AddInt64(scannedIPs, 1)
				s.metrics.IncrIPsScanned()

				for _, protocol := range protocols {
					proxy, err := s.validator.ValidateProxy(ip, port, protocol)
					if err != nil {
						s.metrics.IncrProxiesFailed()
						continue
					}

					// 记录验证成功
					s.metrics.IncrProxiesValidated()
					s.metrics.IncrProxiesByProtocol(proxy.Protocol)
					s.metrics.IncrProxiesByAnonymity(string(proxy.AnonymityLevel))
					s.metrics.RecordLatency(proxy.Speed)

					// 准确性兜底：对已验证代理做独立二次校验
					if s.postValidator != nil {
						if !s.postValidator.PostValidate(proxy) {
							s.metrics.IncrProxiesFailed()
							logger.Debug("二次校验未通过，跳过上报",
								zap.String("ip", ip),
								zap.Int("port", port),
								zap.String("protocol", protocol))
							continue
						}
						s.metrics.IncrProxiesPostValid()
					}

					apiProxy := &api.Proxy{
						IP:          proxy.IP,
						Port:        proxy.Port,
						Protocol:    proxy.Protocol,
						Status:      proxy.Status,
						Speed:       int(proxy.Speed),
						RequireAuth: proxy.RequireAuth,
						Anonymity:   string(proxy.AnonymityLevel),
					}

					rep.Report(apiProxy)
					atomic.AddInt64(foundProxies, 1)
				}
			}(ip, port)
		}
	}

	wg.Wait()
}
```

- [ ] **Step 3: 在 ip_scanner_task.go 添加 metrics 埋点和 anonymity 字段**

文件: `free-proxy-scanner/internal/scanner/ip_scanner_task.go`

在 scanIPTask 函数中添加相同的 metrics 记录，并在构建 apiProxy 时填入 Anonymity 字段：

```go
// 在 proxy 验证成功后添加
apiProxy := &api.Proxy{
	IP:          proxy.IP,
	Port:        proxy.Port,
	Protocol:    proxy.Protocol,
	Status:      proxy.Status,
	Speed:       int(proxy.Speed),
	RequireAuth: proxy.RequireAuth,
	Anonymity:   string(proxy.AnonymityLevel),
}
```

- [ ] **Step 4: 在 scan.go 中创建共享 Metrics 实例并注入**

文件: `free-proxy-scanner/cmd/scanner/cmd/scan.go`

修改 runScan 函数，创建共享 Metrics 实例，注入到 Scanner 和 heartbeatLoop：

在 Scanner 创建后获取 Metrics：
```go
var scannerMetrics *metrics.ScannerMetrics
if cfg.Scanner.ScannerType == "ip_pool" {
	ipScanner := scanner.NewIPScanner(cfg, apiClient)
	sc = ipScanner
	scannerMetrics = ipScanner.GetMetrics()
} else {
	originalScanner := scanner.NewScanner(cfg, apiClient)
	sc = originalScanner
	scannerMetrics = originalScanner.GetMetrics()
}

// 修改 heartbeatLoop 调用
go heartbeatLoop(ctx, apiClient, cfg, scannerMetrics)
```

- [ ] **Step 5: 验证完整流水线集成**
Run: `cd free-proxy-scanner && go build ./...`
Expected:
  - Exit code: 0

- [ ] **Step 6: 运行测试验证无回归**
Run: `cd free-proxy-scanner && go test -short -count=1 $(go list ./... | grep -v '/test$') 2>&1 | grep -E "(FAIL|ok)" | sort`
Expected:
  - Exit code: 0
  - No "FAIL" lines

- [ ] **Step 7: 提交**
Run: `cd free-proxy-scanner && git add -A && git commit -m "feat(scanner): wire metrics and anonymity into full scan pipeline

- Add ScannerMetrics to Scanner struct and inject into batch processor
- Record metrics at every pipeline stage: port scan, validation, post-validation
- Track per-protocol and per-anonymity proxy counts
- Fill api.Proxy.Anonymity field from validator.Proxy.AnonymityLevel
- Share Metrics instance between Scanner and heartbeatLoop
- Pass metrics to Reporter for API success/failure counting

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`

---

### Task 5: 验证端到端度量与匿名等级上报

**Depends on:** Task 4
**Files:**
- Create: `free-proxy-scanner/internal/scanner/metrics/metrics_e2e_test.go`
- Modify: `free-proxy-scanner/internal/scanner/validator/anonymity_test.go`（补充匿名等级测试）

- [ ] **Step 1: 创建端到端度量验证测试**

```go
package metrics

import (
	"testing"
	"time"
)

func TestMetricsSnapshot_JsonFields(t *testing.T) {
	m := NewScannerMetrics()
	m.IncrPortsScanned()
	m.IncrPortsScanned()
	m.IncrPortsOpen()
	m.IncrProxiesValidated()
	m.IncrProxiesByProtocol("http")
	m.IncrProxiesByProtocol("socks5")
	m.IncrProxiesByAnonymity("elite")
	m.IncrProxiesByAnonymity("anonymous")
	m.RecordLatency(50)
	m.RecordLatency(100)

	snap := m.Snapshot()

	// 验证所有关键字段非零
	if snap.PortsScanned != 2 {
		t.Errorf("PortsScanned: expected 2, got %d", snap.PortsScanned)
	}
	if snap.PortsOpen != 1 {
		t.Errorf("PortsOpen: expected 1, got %d", snap.PortsOpen)
	}
	if snap.ProxiesValidated != 1 {
		t.Errorf("ProxiesValidated: expected 1, got %d", snap.ProxiesValidated)
	}
	if snap.HTTPProxies != 1 {
		t.Errorf("HTTPProxies: expected 1, got %d", snap.HTTPProxies)
	}
	if snap.SOCKS5Proxies != 1 {
		t.Errorf("SOCKS5Proxies: expected 1, got %d", snap.SOCKS5Proxies)
	}
	if snap.EliteProxies != 1 {
		t.Errorf("EliteProxies: expected 1, got %d", snap.EliteProxies)
	}
	if snap.AnonymousProxies != 1 {
		t.Errorf("AnonymousProxies: expected 1, got %d", snap.AnonymousProxies)
	}
	if snap.AvgLatencyMs != 75 {
		t.Errorf("AvgLatencyMs: expected 75, got %d", snap.AvgLatencyMs)
	}
	if snap.UptimeSeconds == 0 {
		t.Error("UptimeSeconds should be > 0")
	}
}

func TestMetricsSnapshot_Uptime(t *testing.T) {
	m := NewScannerMetrics()
	time.Sleep(100 * time.Millisecond)
	snap := m.Snapshot()
	if snap.UptimeSeconds < 0 {
		t.Errorf("UptimeSeconds should be non-negative, got %d", snap.UptimeSeconds)
	}
}
```

- [ ] **Step 2: 补充匿名等级分类测试**

文件: `free-proxy-scanner/internal/scanner/validator/anonymity_test.go`

```go
package validator

import (
	"testing"
)

func TestClassifyAnonymity_Transparent(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n"
	info := ClassifyAnonymity(response, "1.2.3.4")
	if info.Level != AnonymityTransparent {
		t.Errorf("expected transparent, got %s", info.Level)
	}
	if !info.HasForwardedFor {
		t.Error("expected HasForwardedFor=true")
	}
}

func TestClassifyAnonymity_Anonymous(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\nVia: 1.1 proxy\r\n\r\n"
	info := ClassifyAnonymity(response, "1.2.3.4")
	if info.Level != AnonymityAnonymous {
		t.Errorf("expected anonymous, got %s", info.Level)
	}
	if !info.HasVia {
		t.Error("expected HasVia=true")
	}
}

func TestClassifyAnonymity_Elite(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	info := ClassifyAnonymity(response, "1.2.3.4")
	if info.Level != AnonymityElite {
		t.Errorf("expected elite, got %s", info.Level)
	}
}

func TestClassifyAnonymity_Unknown(t *testing.T) {
	info := ClassifyAnonymity("", "1.2.3.4")
	if info.Level != AnonymityUnknown {
		t.Errorf("expected unknown, got %s", info.Level)
	}
}

func TestClassifyAnonymity_ProxyAgent(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\nProxy-Agent: squid/5.7\r\n\r\n"
	info := ClassifyAnonymity(response, "1.2.3.4")
	if info.Level != AnonymityAnonymous {
		t.Errorf("expected anonymous (proxy-agent), got %s", info.Level)
	}
	if !info.HasProxyAgent {
		t.Error("expected HasProxyAgent=true")
	}
}
```

- [ ] **Step 3: 运行全部测试验证**
Run: `cd free-proxy-scanner && go test -short -count=1 $(go list ./... | grep -v '/test$') 2>&1 | grep -E "(FAIL|ok)" | sort`
Expected:
  - Exit code: 0
  - No "FAIL" lines
  - All packages show "ok"

- [ ] **Step 4: 提交**
Run: `cd free-proxy-scanner && git add -A && git commit -m "test(metrics): add e2e metrics verification and anonymity classification tests

- Test MetricsSnapshot covers all key fields
- Test anonymity classification for transparent/anonymous/elite/unknown
- Test proxy-agent header detection
- Verify uptime tracking

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`
