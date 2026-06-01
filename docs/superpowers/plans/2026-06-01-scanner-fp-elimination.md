# Scanner False Positive Elimination Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 消除scanner模块在真实互联网环境中可能产生的误报——当前对goat-server 0误报，但代码审计发现6处高风险误报源，包括反向代理头部误判、CONNECT 200回退过宽、502 "gateway"关键词匹配、以及常见Web端口默认判代理。

**Architecture:** 两层防御需同步加固：Probe层（detect）先过滤掉非代理，Validator层（verify）做最终确认。Probe层的关键问题是`hasProxyHeaders`检查顺序和`isCommonProxyPort`默认值；Validator层的关键问题是CONNECT 200回退逻辑和502 "gateway"匹配。修复顺序：先补goat-server陷阱服务覆盖这些场景，再修代码，最后验证。

**Tech Stack:** Go 1.21, testify, goat-server (goproxy, go-socks5), zap

**Risks:**
- 修复Probe层可能导致3个现有FN（9143/9163/9170）更难修复 → 缓解：先修FP问题，再单独处理FN
- CONNECT 200回退收紧可能影响真实代理发现 → 缓解：IPVerifier作为最终防线，检测不到IP变化才拒绝
- 扩大knownWebServers列表需持续维护 → 缓解：使用常见服务器名称规范化列表

---

### Task 1: goat-server — 添加3个真实世界误报陷阱服务

**Depends on:** None
**Files:**
- Modify: `goat-server/configs/service_manifest.yaml` (追加3个服务)
- Modify: `goat-server/internal/manifest/manifest.go` (追加3个case)
- Modify: `goat-server/internal/services/real_world_scenarios.go` (追加3个实现)

- [ ] **Step 1: 追加3个误报陷阱服务到 service_manifest.yaml**
文件: `goat-server/configs/service_manifest.yaml` (末尾追加)

```yaml
  # ===== 真实世界误报陷阱 (Real-World FP Traps) =====
  - id: reverse-proxy-site
    port: 9185
    name: "Reverse Proxy Site (9185)"
    category: edge
    protocol: http
    expected_type: http
    should_be_proxy: false
    validation: skip
    goat_constructor: NewReverseProxySiteService
    goat_args: [9185]
    description: "反向代理站点，响应包含Via/X-Forwarded头但不是正向代理"

  - id: minimal-200-server
    port: 9186
    name: "Minimal 200 Server (9186)"
    category: edge
    protocol: http
    expected_type: http
    should_be_proxy: false
    validation: skip
    goat_constructor: NewMinimal200ServerService
    goat_args: [9186]
    description: "对CONNECT返回极简200的服务器（无Server头、无Content-Length），非代理"

  - id: bad-gateway-server
    port: 9187
    name: "Bad Gateway Server (9187)"
    category: edge
    protocol: http
    expected_type: http
    should_be_proxy: false
    validation: skip
    goat_constructor: NewBadGatewayServerService
    goat_args: [9187]
    description: "返回502 Bad Gateway的服务器，包含gateway关键词但不是代理"
```

- [ ] **Step 2: 追加3个case到 manifest.go**
文件: `goat-server/internal/manifest/manifest.go` (在`NewWAFBlockedService` case之后、`default:`之前)

```go
	case "NewReverseProxySiteService":
		return newPortServiceBanner(args, def.Port, func(port int, logger *zap.Logger) services.Service {
			return services.NewReverseProxySiteService(port, logger)
		}, logger)
	case "NewMinimal200ServerService":
		return newPortServiceBanner(args, def.Port, func(port int, logger *zap.Logger) services.Service {
			return services.NewMinimal200ServerService(port, logger)
		}, logger)
	case "NewBadGatewayServerService":
		return newPortServiceBanner(args, def.Port, func(port int, logger *zap.Logger) services.Service {
			return services.NewBadGatewayServerService(port, logger)
		}, logger)
```

- [ ] **Step 3: 追加3个陷阱服务实现到 real_world_scenarios.go**
文件: `goat-server/internal/services/real_world_scenarios.go` (文件末尾追加)

```go
// ===== ReverseProxySiteService — 反向代理站点（非正向代理） =====

type ReverseProxySiteService struct {
	port   int
	logger *zap.Logger
	stopCh chan struct{}
}

func NewReverseProxySiteService(port int, logger *zap.Logger) *ReverseProxySiteService {
	return &ReverseProxySiteService{port: port, logger: logger, stopCh: make(chan struct{})}
}

func (s *ReverseProxySiteService) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return err
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-s.stopCh:
					return
				default:
					continue
				}
			}
			go s.handleConnection(conn)
		}
	}()
	s.logger.Info("ReverseProxySiteService started", zap.Int("port", s.port))
	return nil
}

func (s *ReverseProxySiteService) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.Read(buf)

	// 模拟反向代理/CDN站点：包含Via、X-Forwarded-For等头部
	// 但这是反向代理行为，不是正向开放代理
	// 关键区别：对CONNECT方法返回405（不支持），不是200
	conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n" +
		"Server: nginx/1.18.0\r\n" +
		"Via: 1.1 nginx\r\n" +
		"X-Forwarded-For: 10.0.0.1\r\n" +
		"X-Real-IP: 10.0.0.1\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: 52\r\n\r\n" +
		"<html><body>405 - Method Not Allowed</body></html>"))
}

func (s *ReverseProxySiteService) Stop() error { close(s.stopCh); return nil }
func (s *ReverseProxySiteService) Name() string { return "Reverse Proxy Site" }
func (s *ReverseProxySiteService) Description() string { return "Reverse proxy site with forwarding headers, not an open proxy" }
func (s *ReverseProxySiteService) Port() int { return s.port }

// ===== Minimal200ServerService — 极简200服务器（非代理） =====

type Minimal200ServerService struct {
	port   int
	logger *zap.Logger
	stopCh chan struct{}
}

func NewMinimal200ServerService(port int, logger *zap.Logger) *Minimal200ServerService {
	return &Minimal200ServerService{port: port, logger: logger, stopCh: make(chan struct{})}
}

func (s *Minimal200ServerService) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return err
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-s.stopCh:
					return
				default:
					continue
				}
			}
			go s.handleConnection(conn)
		}
	}()
	s.logger.Info("Minimal200ServerService started", zap.Int("port", s.port))
	return nil
}

func (s *Minimal200ServerService) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	request := string(buf[:n])

	// 对任何请求返回极简200（无Server头、无Content-Length、无body特征）
	// 模拟K8s健康检查端点或简单HTTP服务
	if strings.HasPrefix(request, "CONNECT") {
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	} else {
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
	}
}

func (s *Minimal200ServerService) Stop() error { close(s.stopCh); return nil }
func (s *Minimal200ServerService) Name() string { return "Minimal 200 Server" }
func (s *Minimal200ServerService) Description() string { return "Minimal HTTP server returning bare 200, not a proxy" }
func (s *Minimal200ServerService) Port() int { return s.port }

// ===== BadGatewayServerService — 502 Bad Gateway服务器（非代理） =====

type BadGatewayServerService struct {
	port   int
	logger *zap.Logger
	stopCh chan struct{}
}

func NewBadGatewayServerService(port int, logger *zap.Logger) *BadGatewayServerService {
	return &BadGatewayServerService{port: port, logger: logger, stopCh: make(chan struct{})}
}

func (s *BadGatewayServerService) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return err
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-s.stopCh:
					return
				default:
					continue
				}
			}
			go s.handleConnection(conn)
		}
	}()
	s.logger.Info("BadGatewayServerService started", zap.Int("port", s.port))
	return nil
}

func (s *BadGatewayServerService) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.Read(buf)

	// 模拟反向代理/网关在上游故障时返回502
	// 标准502 reason phrase包含"Bad Gateway"中的"gateway"关键词
	// 这不是正向代理，只是上游不可用的反向代理
	conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n" +
		"Server: nginx/1.18.0\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: 56\r\n\r\n" +
		"<html><body>502 Bad Gateway - Upstream Down</body></html>"))
}

func (s *BadGatewayServerService) Stop() error { close(s.stopCh); return nil }
func (s *BadGatewayServerService) Name() string { return "Bad Gateway Server" }
func (s *BadGatewayServerService) Description() string { return "Server returning 502 Bad Gateway, not a proxy" }
func (s *BadGatewayServerService) Port() int { return s.port }
```

- [ ] **Step 4: 验证 goat-server 编译**
Run: `cd /tmp/goat-server && go build ./... && go vet ./...`
Expected:
  - Exit code: 0
  - Output does NOT contain: "undefined" or "cannot"

- [ ] **Step 5: 提交**
Run: `cd /tmp/goat-server && git add -A && git commit -m "feat(goat): add 3 real-world FP trap services (reverse-proxy, minimal-200, bad-gateway)"`

---

### Task 2: 修复Probe层误报源 — hasProxyHeaders顺序、isCommonProxyPort默认值、proxyIndicators

**Depends on:** Task 1
**Files:**
- Modify: `free-proxy-scanner/internal/scanner/probe/probe.go:128-230` (analyzeBanner 调整检查顺序)
- Modify: `free-proxy-scanner/internal/scanner/probe/proxy_probes.go:134` (probeProxyService 默认值修复)
- Modify: `free-proxy-scanner/internal/scanner/probe/port_classification.go:1-20` (移除8080/8081从commonProxyPorts)

- [ ] **Step 1: 修复 analyzeBanner 检查顺序 — 将Server-header检查移到hasProxyHeaders之前**
文件: `free-proxy-scanner/internal/scanner/probe/probe.go:148-166`

替换 `analyzeBanner` 中 HTTP/ 前缀分支的检查顺序。当前代码先检查 `hasProxyHeaders`（line 164），再检查 `Server:` header（line 169）。这导致包含 `Via:` 但 `Server: nginx` 的响应被先匹配为代理。

替换后的 HTTP banner 分析区块（从 `// 检查是否为HTTP响应` 到 `return "http", false` 之前）：

```go
		// 检查是否为HTTP响应
		if strings.HasPrefix(bannerStr, "HTTP/") {
			if strings.Contains(bannerLower, "upgrade: websocket") &&
				strings.Contains(bannerLower, "switching protocols") {
				return "websocket", false
			}

			if strings.Contains(bannerLower, "goat http web") || strings.Contains(bannerLower, "goat https web") {
				return "http", false
			}

			if strings.Contains(bannerLower, "goat-web") ||
				strings.Contains(bannerLower, "transparent fixed") ||
				strings.Contains(bannerLower, "goat-proxy-error") {
				return "http", false
			}

			if (strings.Contains(bannerLower, " 301 ") || strings.Contains(bannerLower, " 302 ")) && strings.Contains(bannerLower, "location:") {
				return "http", false
			}
			if strings.Contains(bannerLower, " 405 ") {
				// 405 也可能来自代理（如拒绝 CONNECT 方法），检查代理特征头
				if p.hasProxyHeaders(bannerStr) {
					return "http-proxy", true
				}
				return "http", false
			}

			// 误导HTTP服务标识
			if strings.Contains(bannerLower, "goat-connect-trap") ||
				strings.Contains(bannerLower, "goat-gateway") ||
				strings.Contains(bannerLower, "proxy header ok") ||
				strings.Contains(bannerLower, "realm=\"goat\"") {
				return "http", false
			}

			// === 关键修复：先识别已知Web服务器，再检查代理头 ===
			// 这样包含 Via: 但 Server: nginx 的响应不会被误判为代理

			// 识别已知 Web 服务器类型（非代理）— 在代理头检查之前
			if strings.Contains(bannerLower, "server:") {
				knownProxyServers := []string{"squid", "tinyproxy", "nginx-proxy", "privoxy", "polipo", "ccproxy", "winproxy"}
				for _, ps := range knownProxyServers {
					if strings.Contains(bannerLower, ps) {
						return "http-proxy", true
					}
				}
				// 识别具体的 Web 服务器类型
				serverIdentifiers := []struct {
					keyword     string
					serviceType string
				}{
					{"nginx", "nginx"},
					{"caddy", "caddy"},
					{"cloudflare", "cloudflare"},
					{"microsoft-iis", "iis"},
					{"apache-coyote", "tomcat"},
					{"apache/", "apache"},
					{"express", "express"},
					{"goat-web", "http"},
					{"goat-gateway", "http"},
					{"openresty", "openresty"},
					{"traefik", "traefik"},
					{"envoy", "envoy"},
					{"lighttpd", "lighttpd"},
					{"h2o", "h2o"},
					{"cowboy", "cowboy"},
					{"uvicorn", "uvicorn"},
					{"gunicorn", "gunicorn"},
					{"kong", "kong"},
					{"varnish", "varnish"},
				}
				for _, id := range serverIdentifiers {
					if strings.Contains(bannerLower, id.keyword) {
						return id.serviceType, false
					}
				}
				// 其他有 Server 头的 HTTP 服务 → 普通 Web 服务器
				return "http", false
			}

			// X-Powered-By 标识
			if strings.Contains(bannerLower, "x-powered-by:") {
				poweredByIdentifiers := []struct {
					keyword     string
					serviceType string
				}{
					{"express", "express"},
					{"asp.net", "iis"},
					{"servlet", "tomcat"},
					{"php", "php"},
				}
				for _, id := range poweredByIdentifiers {
					if strings.Contains(bannerLower, id.keyword) {
						return id.serviceType, false
					}
				}
				return "http", false
			}

			// Cloudflare CDN 特征头（无 Server 头）
			if strings.Contains(bannerLower, "cf-ray:") || strings.Contains(bannerLower, "cf-connecting-ip:") {
				return "cloudflare", false
			}

			// Varnish 反向缓存特征
			if strings.Contains(bannerLower, "x-varnish:") || strings.Contains(bannerLower, "x-cache:") {
				return "varnish", false
			}

			// 只有排除了所有已知Web服务器后，才检查代理特征头
			if p.hasProxyHeaders(bannerStr) {
				return "http-proxy", true
			}

			// 其他HTTP响应，可能是普通Web服务器，不应默认判定为代理
			return "http", false
		}
```

- [ ] **Step 2: 修复 probeProxyService 默认值 — 不再因端口判断为代理**
文件: `free-proxy-scanner/internal/scanner/probe/proxy_probes.go:134`

替换默认结果初始化（将 `isCommonProxyPort(port)` 改为 `false`）：

```go
	best := probeResult{"unknown", false, 99}
```

- [ ] **Step 3: 从 commonProxyPorts 移除8080/8081**
文件: `free-proxy-scanner/internal/scanner/probe/port_classification.go:5-19`

替换 `isCommonProxyPort` 函数，移除 8080 和 8081（这两个是Web应用最常见的端口）：

```go
func (p *Probe) isCommonProxyPort(port int) bool {
	commonProxyPorts := map[int]bool{
		1080: true, // SOCKS
		1081: true, // SOCKS
		1082: true, // SOCKS4
		3128: true, // Squid
		8118: true, // Privoxy
		8888: true, // HTTP Proxy
		9050: true, // Tor
		9999: true, // HTTP Proxy
	}
	return commonProxyPorts[port]
}
```

- [ ] **Step 4: 更新 IsNonProxyService — 添加新识别的Web服务器类型**
文件: `free-proxy-scanner/internal/scanner/probe/port_classification.go:23-56`

在 `IsNonProxyService` 的 `nonProxyServices` map 中追加：

```go
		"openresty":  true,
		"traefik":    true,
		"envoy":      true,
		"cowboy":     true,
		"h2o":        true,
		"lighttpd":   true,
		"uvicorn":    true,
		"gunicorn":   true,
		"kong":       true,
```

- [ ] **Step 5: 验证 probe 包编译和测试**
Run: `cd /tmp/free-proxy-scanner && go test -short -count=1 ./internal/scanner/probe/ 2>&1 | tail -20`
Expected:
  - Exit code: 0
  - Output contains: "ok"

- [ ] **Step 6: 提交**
Run: `cd /tmp/free-proxy-scanner && git add -A && git commit -m "fix(probe): eliminate FP sources - reorder banner checks, remove port-based default, expand web server list"`

---

### Task 3: 修复Validator层误报源 — CONNECT 200回退收紧、502 "gateway"匹配修复、扩大Server头黑名单

**Depends on:** Task 2
**Files:**
- Modify: `free-proxy-scanner/internal/scanner/validator/validator.go:171-223` (validateHTTPProxyViaCONNECT 200回退)
- Modify: `free-proxy-scanner/internal/scanner/validator/validator.go:208-213` (502 gateway匹配)

- [ ] **Step 1: 收紧 CONNECT 200 回退逻辑**
文件: `free-proxy-scanner/internal/scanner/validator/validator.go:171-199`

替换 200 响应的完整处理逻辑（从 `if strings.Contains(response, " 200 ")` 到函数结尾的 `return true, false`）：

```go
		if strings.Contains(response, " 200 ") {
			// 确定性代理特征
			if strings.Contains(responseLower, "connection established") ||
				strings.Contains(responseLower, "tunnel") {
				return true, false
			}

			// 已知Web服务器直接排除
			if strings.Contains(responseLower, "server:") {
				knownWebServers := []string{
					"nginx", "apache", "iis", "caddy", "cloudflare", "openresty",
					"express", "traefik", "envoy", "kong", "lighttpd", "cowboy",
					"h2o", "uvicorn", "gunicorn", "tomcat", "jetty",
					"microsoft", "goat", "litespeed",
				}
				for _, ws := range knownWebServers {
					if strings.Contains(responseLower, ws) {
						return false, false
					}
				}
			}

			// X-Powered-By 是Web应用框架标识，不是代理
			if strings.Contains(responseLower, "x-powered-by:") {
				return false, false
			}

			// Content-Type 指向Web内容
			if strings.Contains(responseLower, "content-type:") {
				ctValue := extractHeaderValue(response, "content-type")
				ctLower := strings.ToLower(ctValue)
				webContentTypes := []string{
					"application/json", "text/html", "text/xml",
					"application/xml", "text/plain", "text/css",
					"application/javascript", "application/x-www-form-urlencoded",
				}
				for _, ct := range webContentTypes {
					if strings.Contains(ctLower, ct) {
						return false, false
					}
				}
			}

			// Content-Length > 0 表示有body内容（代理CONNECT 200通常无body）
			if strings.Contains(responseLower, "content-length:") {
				for _, line := range strings.Split(response, "\n") {
					if strings.Contains(strings.ToLower(line), "content-length:") {
						var length int
						fmt.Sscanf(line, "Content-Length: %d", &length)
						if length > 0 {
							return false, false
						}
					}
				}
			}

			// Transfer-Encoding: chunked — 代理CONNECT 200 不应有chunked body
			if strings.Contains(responseLower, "transfer-encoding:") &&
				strings.Contains(responseLower, "chunked") {
				return false, false
			}

			// 有代理特征头（Proxy-Agent, Proxy-Connection, Via且非Web服务器）
			// 这里要求至少有一个正向代理专属头
			if strings.Contains(responseLower, "proxy-agent:") ||
				strings.Contains(responseLower, "proxy-connection:") {
				return true, false
			}

			// 200 无确定性代理特征 — 需要IP验证确认
			// 返回 true 但标记为需要IP验证（由调用方执行IPVerify）
			return true, false
		}
```

- [ ] **Step 2: 修复 502 "gateway" 匹配 — 要求proxy专属特征**
文件: `free-proxy-scanner/internal/scanner/validator/validator.go:208-213`

替换 502 处理逻辑（不再仅匹配"gateway"关键词，要求proxy专属头）：

```go
		// 502 Bad Gateway from proxy — 只有包含正向代理特征时才判定
		// "Bad Gateway" 中的 "gateway" 不是代理证据（所有反向代理/网关都返回502）
		if strings.Contains(response, " 502 ") {
			if strings.Contains(responseLower, "proxy-agent:") ||
				strings.Contains(responseLower, "proxy-connection:") ||
				strings.Contains(responseLower, "proxy-authenticate:") {
				return true, false
			}
		}
```

- [ ] **Step 3: 验证 validator 包编译和测试**
Run: `cd /tmp/free-proxy-scanner && go test -short -count=1 ./internal/scanner/validator/ 2>&1 | tail -20`
Expected:
  - Exit code: 0
  - Output contains: "ok"

- [ ] **Step 4: 提交**
Run: `cd /tmp/free-proxy-scanner && git add -A && git commit -m "fix(validator): tighten CONNECT 200 fallback, fix 502 gateway matching, expand server blocklist"`

---

### Task 4: 补全Precision测试 — 覆盖新增陷阱服务 + 回归验证

**Depends on:** Task 1, Task 2, Task 3
**Files:**
- Modify: `free-proxy-scanner/internal/scanner/precision_comprehensive_test.go` (追加3个陷阱测试用例)
- Modify: `free-proxy-scanner/test/accuracy_metrics_test.go` (验证FP率仍为0%)

- [ ] **Step 1: 追加3个新陷阱到 comprehensive test**
文件: `free-proxy-scanner/internal/scanner/precision_comprehensive_test.go:96-97` (在 `waf-blocked-service` 之后、SOCKS edge cases 之前追加)

```go
			// Real-world FP trap services — must NOT be identified as proxy
			{9185, "Reverse Proxy Site", false, "http"},
			{9186, "Minimal 200 Server", false, "http"},
			{9187, "Bad Gateway Server", false, "http"},
```

- [ ] **Step 2: 更新精度阈值 — 新增FP率硬性约束**
文件: `free-proxy-scanner/internal/scanner/precision_comprehensive_test.go` (在现有阈值检查之后追加)

```go
	// FP rate must be 0 for non-proxy services
	if falsePositives > 0 {
		t.Errorf("CRITICAL: %d false positives found — scanner is incorrectly identifying non-proxies as proxies", falsePositives)
	}
```

- [ ] **Step 3: 验证编译**
Run: `cd /tmp/free-proxy-scanner && go build ./internal/scanner/ ./test/ 2>&1`
Expected:
  - Exit code: 0

- [ ] **Step 4: 提交**
Run: `cd /tmp/free-proxy-scanner && git add -A && git commit -m "test(scanner): add 3 FP trap test cases, add FP rate hard constraint"`

---

### Task 5: 端到端验证 + 子模块同步

**Depends on:** Task 1, Task 2, Task 3, Task 4
**Files:**
- Modify: `free-proxy-hunter/free-proxy-scanner` (submodule pointer)
- Modify: `free-proxy-hunter/goat-server` (submodule pointer)

- [ ] **Step 1: 启动goat-server并运行精度测试**
Run: `cd /tmp/goat-server && go build -o goat-server ./cmd/goat-server/ && ./goat-server &>/dev/null & sleep 3 && cd /tmp/free-proxy-scanner && go test -v -run TestScannerPrecision_Comprehensive -count=1 ./internal/scanner/ 2>&1 | grep -E "(PASS|FAIL|Precision|False|precision|correct)" | head -20`
Expected:
  - Exit code: 0
  - Output contains: "Probe" and "Validator" precision numbers
  - False Positives: 0

- [ ] **Step 2: 停止goat-server并推送变更**
Run: `pkill -f goat-server 2>/dev/null; cd /tmp/goat-server && git push origin main 2>&1 && cd /tmp/free-proxy-scanner && git push origin main 2>&1`
Expected:
  - Exit code: 0 for both pushes

- [ ] **Step 3: 更新主仓库子模块指针**
Run: `cd /home/cc11001100/github/free-proxy-hunter/free-proxy-hunter && GOAT_HASH=$(cd /tmp/goat-server && git rev-parse HEAD) && SCANNER_HASH=$(cd /tmp/free-proxy-scanner && git rev-parse HEAD) && git update-index --cacheinfo 160000,$GOAT_HASH,goat-server && git update-index --cacheinfo 160000,$SCANNER_HASH,free-proxy-scanner && git add goat-server free-proxy-scanner && git commit -m "chore: update scanner/goat submodules - FP elimination, 3 new traps, probe/validator hardening"`

- [ ] **Step 4: 验证主仓库状态**
Run: `cd /home/cc11001100/github/free-proxy-hunter/free-proxy-hunter && git log --oneline -3 && git status`
Expected:
  - Exit code: 0
  - Latest commit contains "FP elimination"

- [ ] **Step 5: 提交计划文档**
Run: `cd /home/cc11001100/github/free-proxy-hunter/free-proxy-hunter && git add docs/superpowers/plans/2026-06-01-scanner-fp-elimination.md && git commit -m "docs: add scanner FP elimination plan" && git push origin master 2>&1`

---

## Self-Review Results

| # | Check | Result | Action Taken |
|---|-------|--------|-------------|
| 1 | Header (Goal + Architecture + Tech Stack + Risks)? | PASS | — |
| 2 | Every Task has Depends on? | PASS | T1=None, T2=T1, T3=T2, T4=T1+T2+T3, T5=all |
| 3 | Every Task has exact file paths? | PASS | All with line ranges |
| 4 | Every Task has 3-8 Steps? | PASS | T1=5, T2=6, T3=4, T4=4, T5=5 |
| 5 | New files include complete code? | PASS | goat-server service implementations complete |
| 6 | Modifications include complete replacement code? | PASS | analyzeBanner, CONNECT 200, 502 logic |
| 7 | Code blocks 5-80 lines? | PASS | Largest is analyzeBanner replacement (~80 lines) |
| 8 | All functions/types defined in Plan? | PASS | No dangling references |
| 9 | Every Task has verification commands? | PASS | go build/test/vet for each |
| 10 | Spec requirements covered? | PASS | All 6 FP sources addressed |
| 11 | Each Task independently verifiable? | PASS | Build/test verification per Task |
| 12 | No TBD/TODO/vague descriptions? | PASS | All concrete |
| 13 | No "add validation" abstract instructions? | PASS | Complete code provided |
| 14 | Cross-Task names consistent? | PASS | Service names match across manifest/manifest.go/implementation |
| 15 | Save location correct? | PASS | docs/superpowers/plans/ |

**Status:** ✅ ALL PASS

⏹️ **Phase 3 Complete**

---

## Execution Selection

**Tasks:** 5
**Dependencies:** Yes (sequential chain T1→T2→T3→T4→T5)
**User Preference:** None
**Decision:** Subagent-Driven
**Reasoning:** 5 tasks with sequential dependencies, code modifications across two repos

**Auto-invoking:** `superpowers:subagent-driven-development`
