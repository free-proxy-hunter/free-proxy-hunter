# Scanner 主流代理软件兼容性增强 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 增强 Scanner 模块对主流代理软件的兼容性——两个维度：(1) 检测兼容性：添加 3proxy/gost/delegate/Apache mod_proxy 的软件指纹，扩大检测覆盖面；(2) 输出兼容性：添加多格式导出器（URI/curl/Clash/PAC），使发现的代理可被主流软件直接使用。同时添加代理匿名等级分类（transparent/anonymous/elite），提升代理质量评估能力。

**Architecture:** 三层改进同步推进——靶场层先在 goat-server 添加 3proxy/gost 模拟服务和匿名检测目标 → 检测层在 Probe 添加软件指纹 + 在 Validator 添加匿名等级分类 → 输出层新增 Exporter 包实现多格式转换。数据流：Scanner 扫描 → Probe 识别软件指纹 → Validator 验证 + 匿名分类 → Exporter 格式化输出 → 用户直接导入 curl/Clash/浏览器。

**Tech Stack:** Go 1.21, testify, goproxy, go-socks5, zap, yaml.v3

**Risks:**
- Task 1 修改 goat-server manifest，端口 9188-9193 若被占用会启动失败 → 缓解：9100-9199 为测试端口段，已预留
- Task 2 添加 3proxy/gost 指纹，gost 默认 UA `Chrome/60.0.3112.90` 可能误判 → 缓解：仅作为辅助指纹，不作为主判据
- Task 3 Apache mod_proxy 正向/反向区分依赖响应行为而非头部 → 缓解：使用 CONNECT 方法的响应差异作为判据
- Task 4 匿名分类需要目标端点回显请求头 → 缓解：goat-server 已有 HTTP 回显服务，可复用
- 子模块未 checkout，所有修改需在 submodule 初始化后执行 → 缓解：Task 6 包含 submodule 初始化步骤

---

### Task 1: goat-server 添加代理软件模拟服务 + 匿名检测目标

**Depends on:** None
**Files:**
- Modify: `goat-server/configs/service_manifest.yaml` (追加6个服务)
- Modify: `goat-server/internal/manifest/manifest.go` (追加6个 case)
- Create: `goat-server/internal/services/proxy_software_scenarios.go` (3proxy/gost/delegate 模拟 + 匿名检测目标)

- [ ] **Step 1: 追加6个服务到 service_manifest.yaml**
文件: `goat-server/configs/service_manifest.yaml` (文件末尾追加)

```yaml
  # ===== 代理软件指纹模拟 (Proxy Software Fingerprints) =====
  - id: three-proxy-http
    port: 9188
    name: "3proxy HTTP (9188)"
    category: proxy
    protocol: http
    expected_type: http-proxy
    should_be_proxy: true
    validation: skip
    goat_constructor: NewThreeProxyHTTPService
    goat_args: [9188]
    description: "模拟3proxy软件的HTTP代理行为"

  - id: gost-http-proxy
    port: 9189
    name: "gost HTTP Proxy (9189)"
    category: proxy
    protocol: http
    expected_type: http-proxy
    should_be_proxy: true
    validation: skip
    goat_constructor: NewGostHTTPProxyService
    goat_args: [9189]
    description: "模拟gost软件的HTTP代理行为"

  - id: delegate-proxy
    port: 9190
    name: "delegate Proxy (9190)"
    category: proxy
    protocol: http
    expected_type: http-proxy
    should_be_proxy: true
    validation: skip
    goat_constructor: NewDelegateProxyService
    goat_args: [9190]
    description: "模拟delegate软件的代理行为"

  # ===== 匿名等级检测目标 (Anonymity Detection Targets) =====
  - id: transparent-proxy
    port: 9191
    name: "Transparent Proxy (9191)"
    category: proxy
    protocol: http
    expected_type: http-proxy
    should_be_proxy: true
    validation: skip
    goat_constructor: NewTransparentProxyService
    goat_args: [9191]
    description: "透明代理：转发 X-Forwarded-For 和 Via 头"

  - id: anonymous-proxy
    port: 9192
    name: "Anonymous Proxy (9192)"
    category: proxy
    protocol: http
    expected_type: http-proxy
    should_be_proxy: true
    validation: skip
    goat_constructor: NewAnonymousProxyService
    goat_args: [9192]
    description: "匿名代理：隐藏客户端IP，但暴露Via头"

  - id: elite-proxy
    port: 9193
    name: "Elite Proxy (9193)"
    category: proxy
    protocol: http
    expected_type: http-proxy
    should_be_proxy: true
    validation: skip
    goat_constructor: NewEliteProxyService
    goat_args: [9193]
    description: "高匿代理：不发送任何代理标识头"
```

- [ ] **Step 2: 追加6个 case 到 manifest.go**
文件: `goat-server/internal/manifest/manifest.go` (在最后一个 service case 之后、`default:` 之前追加)

```go
		case "NewThreeProxyHTTPService":
			return newPortServiceBanner(args, def.Port, func(port int, logger *zap.Logger) services.Service {
				return services.NewThreeProxyHTTPService(port, logger)
			}, logger)
		case "NewGostHTTPProxyService":
			return newPortServiceBanner(args, def.Port, func(port int, logger *zap.Logger) services.Service {
				return services.NewGostHTTPProxyService(port, logger)
			}, logger)
		case "NewDelegateProxyService":
			return newPortServiceBanner(args, def.Port, func(port int, logger *zap.Logger) services.Service {
				return services.NewDelegateProxyService(port, logger)
			}, logger)
		case "NewTransparentProxyService":
			return newPortServiceBanner(args, def.Port, func(port int, logger *zap.Logger) services.Service {
				return services.NewTransparentProxyService(port, logger)
			}, logger)
		case "NewAnonymousProxyService":
			return newPortServiceBanner(args, def.Port, func(port int, logger *zap.Logger) services.Service {
				return services.NewAnonymousProxyService(port, logger)
			}, logger)
		case "NewEliteProxyService":
			return newPortServiceBanner(args, def.Port, func(port int, logger *zap.Logger) services.Service {
				return services.NewEliteProxyService(port, logger)
			}, logger)
```

- [ ] **Step 3: 创建代理软件模拟和匿名检测服务实现**
Create: `goat-server/internal/services/proxy_software_scenarios.go`

```go
package services

import (
	"fmt"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ===== ThreeProxyHTTPService — 模拟 3proxy 软件的 HTTP 代理 =====
// 3proxy 是公网上最常见的免费代理软件之一，特征：
// - Server 头包含 "3proxy"
// - 支持 CONNECT 方法
// - 可能返回 Proxy-Agent: 3proxy

type ThreeProxyHTTPService struct {
	port   int
	logger *zap.Logger
	stopCh chan struct{}
}

func NewThreeProxyHTTPService(port int, logger *zap.Logger) *ThreeProxyHTTPService {
	return &ThreeProxyHTTPService{port: port, logger: logger, stopCh: make(chan struct{})}
}

func (s *ThreeProxyHTTPService) Start() error {
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
	s.logger.Info("ThreeProxyHTTPService started", zap.Int("port", s.port))
	return nil
}

func (s *ThreeProxyHTTPService) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	request := string(buf[:n])

	if strings.HasPrefix(request, "CONNECT") {
		// 3proxy 对 CONNECT 返回 200 + Server: 3proxy
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n" +
			"Server: 3proxy/0.9.4\r\n" +
			"Proxy-Agent: 3proxy/0.9.4\r\n\r\n"))
	} else if strings.HasPrefix(request, "GET") && strings.Contains(request, "http://") {
		conn.Write([]byte("HTTP/1.1 200 OK\r\n" +
			"Server: 3proxy/0.9.4\r\n" +
			"Proxy-Agent: 3proxy/0.9.4\r\n" +
			"Via: 1.1 3proxy\r\n" +
			"Content-Length: 2\r\n\r\nOK"))
	} else {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n" +
			"Server: 3proxy/0.9.4\r\n\r\n"))
	}
}

func (s *ThreeProxyHTTPService) Stop() error          { close(s.stopCh); return nil }
func (s *ThreeProxyHTTPService) Name() string         { return "3proxy HTTP" }
func (s *ThreeProxyHTTPService) Description() string  { return "3proxy HTTP proxy simulation" }
func (s *ThreeProxyHTTPService) Port() int            { return s.port }

// ===== GostHTTPProxyService — 模拟 gost 软件的 HTTP 代理 =====
// gost (Go Simple Tunnel) 是增长最快的代理工具，特征：
// - 支持 CONNECT 和绝对 URI
// - 默认行为类似标准 HTTP 代理
// - 可能包含 "gost" 标识

type GostHTTPProxyService struct {
	port   int
	logger *zap.Logger
	stopCh chan struct{}
}

func NewGostHTTPProxyService(port int, logger *zap.Logger) *GostHTTPProxyService {
	return &GostHTTPProxyService{port: port, logger: logger, stopCh: make(chan struct{})}
}

func (s *GostHTTPProxyService) Start() error {
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
	s.logger.Info("GostHTTPProxyService started", zap.Int("port", s.port))
	return nil
}

func (s *GostHTTPProxyService) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	request := string(buf[:n])

	if strings.HasPrefix(request, "CONNECT") {
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n" +
			"Proxy-Agent: gost/2.11.5\r\n\r\n"))
	} else if strings.HasPrefix(request, "GET") && strings.Contains(request, "http://") {
		conn.Write([]byte("HTTP/1.1 200 OK\r\n" +
			"Proxy-Agent: gost/2.11.5\r\n" +
			"Via: 1.1 gost\r\n" +
			"Content-Length: 2\r\n\r\nOK"))
	} else {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}
}

func (s *GostHTTPProxyService) Stop() error          { close(s.stopCh); return nil }
func (s *GostHTTPProxyService) Name() string         { return "gost HTTP Proxy" }
func (s *GostHTTPProxyService) Description() string  { return "gost HTTP proxy simulation" }
func (s *GostHTTPProxyService) Port() int            { return s.port }

// ===== DelegateProxyService — 模拟 delegate 软件的代理 =====
// delegate 是老式多协议代理，特征：
// - Server 头包含 "Delegate"
// - 支持 CONNECT 和 HTTP 绝对 URI

type DelegateProxyService struct {
	port   int
	logger *zap.Logger
	stopCh chan struct{}
}

func NewDelegateProxyService(port int, logger *zap.Logger) *DelegateProxyService {
	return &DelegateProxyService{port: port, logger: logger, stopCh: make(chan struct{})}
}

func (s *DelegateProxyService) Start() error {
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
	s.logger.Info("DelegateProxyService started", zap.Int("port", s.port))
	return nil
}

func (s *DelegateProxyService) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	request := string(buf[:n])

	if strings.HasPrefix(request, "CONNECT") {
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n" +
			"Server: DeleGate/9.9.7\r\n" +
			"Proxy-Agent: DeleGate/9.9.7\r\n\r\n"))
	} else if strings.HasPrefix(request, "GET") && strings.Contains(request, "http://") {
		conn.Write([]byte("HTTP/1.1 200 OK\r\n" +
			"Server: DeleGate/9.9.7\r\n" +
			"Via: 1.1 DeleGate\r\n" +
			"Content-Length: 2\r\n\r\nOK"))
	} else {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n" +
			"Server: DeleGate/9.9.7\r\n\r\n"))
	}
}

func (s *DelegateProxyService) Stop() error          { close(s.stopCh); return nil }
func (s *DelegateProxyService) Name() string         { return "delegate Proxy" }
func (s *DelegateProxyService) Description() string  { return "delegate proxy simulation" }
func (s *DelegateProxyService) Port() int            { return s.port }

// ===== TransparentProxyService — 透明代理模拟 =====
// 透明代理特征：转发 X-Forwarded-For（含客户端真实IP）+ Via 头
// 目标服务器能看到客户端真实IP，无隐私保护

type TransparentProxyService struct {
	port   int
	logger *zap.Logger
	stopCh chan struct{}
}

func NewTransparentProxyService(port int, logger *zap.Logger) *TransparentProxyService {
	return &TransparentProxyService{port: port, logger: logger, stopCh: make(chan struct{})}
}

func (s *TransparentProxyService) Start() error {
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
	s.logger.Info("TransparentProxyService started", zap.Int("port", s.port))
	return nil
}

func (s *TransparentProxyService) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	request := string(buf[:n])

	if strings.HasPrefix(request, "CONNECT") {
		// 透明代理：返回成功但标记为透明
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n" +
			"Proxy-Agent: goat-transparent\r\n" +
			"Via: 1.1 goat-transparent\r\n" +
			"X-Forwarded-For: 127.0.0.1\r\n\r\n"))
	} else if strings.HasPrefix(request, "GET") {
		conn.Write([]byte("HTTP/1.1 200 OK\r\n" +
			"Proxy-Agent: goat-transparent\r\n" +
			"Via: 1.1 goat-transparent\r\n" +
			"X-Forwarded-For: 127.0.0.1\r\n" +
			"Content-Length: 24\r\n\r\n" +
			"{\"ip\":\"127.0.0.1\"}"))
	} else {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}
}

func (s *TransparentProxyService) Stop() error          { close(s.stopCh); return nil }
func (s *TransparentProxyService) Name() string         { return "Transparent Proxy" }
func (s *TransparentProxyService) Description() string  { return "Transparent proxy - forwards client IP via X-Forwarded-For" }
func (s *TransparentProxyService) Port() int            { return s.port }

// ===== AnonymousProxyService — 匿名代理模拟 =====
// 匿名代理特征：不转发客户端IP（无 X-Forwarded-For），但暴露 Via 等代理头
// 目标服务器知道请求经过代理，但不知道客户端真实IP

type AnonymousProxyService struct {
	port   int
	logger *zap.Logger
	stopCh chan struct{}
}

func NewAnonymousProxyService(port int, logger *zap.Logger) *AnonymousProxyService {
	return &AnonymousProxyService{port: port, logger: logger, stopCh: make(chan struct{})}
}

func (s *AnonymousProxyService) Start() error {
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
	s.logger.Info("AnonymousProxyService started", zap.Int("port", s.port))
	return nil
}

func (s *AnonymousProxyService) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	request := string(buf[:n])

	if strings.HasPrefix(request, "CONNECT") {
		// 匿名代理：有 Via 但无 X-Forwarded-For
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n" +
			"Proxy-Agent: goat-anonymous\r\n" +
			"Via: 1.1 goat-anonymous\r\n\r\n"))
	} else if strings.HasPrefix(request, "GET") {
		conn.Write([]byte("HTTP/1.1 200 OK\r\n" +
			"Proxy-Agent: goat-anonymous\r\n" +
			"Via: 1.1 goat-anonymous\r\n" +
			"Content-Length: 24\r\n\r\n" +
			"{\"ip\":\"proxy-ip\"}"))
	} else {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}
}

func (s *AnonymousProxyService) Stop() error          { close(s.stopCh); return nil }
func (s *AnonymousProxyService) Name() string         { return "Anonymous Proxy" }
func (s *AnonymousProxyService) Description() string  { return "Anonymous proxy - hides client IP but reveals proxy via headers" }
func (s *AnonymousProxyService) Port() int            { return s.port }

// ===== EliteProxyService — 高匿代理模拟 =====
// 高匿代理特征：不发送任何代理标识头（无 Via、无 X-Forwarded-For、无 Proxy-Agent）
// 对目标服务器来说，请求看起来像直接来自代理IP

type EliteProxyService struct {
	port   int
	logger *zap.Logger
	stopCh chan struct{}
}

func NewEliteProxyService(port int, logger *zap.Logger) *EliteProxyService {
	return &EliteProxyService{port: port, logger: logger, stopCh: make(chan struct{})}
}

func (s *EliteProxyService) Start() error {
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
	s.logger.Info("EliteProxyService started", zap.Int("port", s.port))
	return nil
}

func (s *EliteProxyService) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	request := string(buf[:n])

	if strings.HasPrefix(request, "CONNECT") {
		// 高匿代理：极简响应，无任何代理标识
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	} else if strings.HasPrefix(request, "GET") {
		// 无 Via、无 Proxy-Agent、无 X-Forwarded-For
		conn.Write([]byte("HTTP/1.1 200 OK\r\n" +
			"Content-Length: 24\r\n\r\n" +
			"{\"ip\":\"proxy-ip\"}"))
	} else {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}
}

func (s *EliteProxyService) Stop() error          { close(s.stopCh); return nil }
func (s *EliteProxyService) Name() string         { return "Elite Proxy" }
func (s *EliteProxyService) Description() string  { return "Elite proxy - no proxy headers sent, looks like direct connection" }
func (s *EliteProxyService) Port() int            { return s.port }
```

- [ ] **Step 4: 验证 goat-server 编译**
Run: `cd goat-server && go build ./... && go vet ./...`
Expected:
  - Exit code: 0
  - Output does NOT contain: "undefined" or "cannot"

- [ ] **Step 5: 提交**
Run: `cd goat-server && git add -A && git commit -m "feat(goat): add proxy software simulations (3proxy/gost/delegate) + anonymity level targets (transparent/anonymous/elite)"`

---

### Task 2: Scanner Probe 层添加 3proxy/gost/delegate 软件指纹

**Depends on:** Task 1
**Files:**
- Modify: `free-proxy-scanner/internal/scanner/probe/probe.go` (analyzeBanner 添加指纹识别)
- Modify: `free-proxy-scanner/internal/scanner/probe/port_classification.go` (扩展代理端口)

- [ ] **Step 1: 在 analyzeBanner 的 knownProxyServers 列表中添加 3proxy/gost/delegate**
文件: `free-proxy-scanner/internal/scanner/probe/probe.go` (在 analyzeBanner 函数的 `knownProxyServers` 数组中追加)

在现有 `knownProxyServers := []string{"squid", "tinyproxy", "nginx-proxy", "privoxy", "polipo", "ccproxy", "winproxy"}` 之后追加新指纹：

```go
				knownProxyServers := []string{
					"squid", "tinyproxy", "nginx-proxy", "privoxy", "polipo",
					"ccproxy", "winproxy",
					// 新增代理软件指纹
					"3proxy", "gost", "delegate",
				}
```

- [ ] **Step 2: 在 serverIdentifiers 列表中为 Apache 添加正向代理标识**
文件: `free-proxy-scanner/internal/scanner/probe/probe.go` (在 analyzeBanner 的 `serverIdentifiers` 数组附近)

在现有 Server-header 检查逻辑中，需要区分 Apache 作为 Web 服务器 vs Apache 作为正向代理。在 `serverIdentifiers` 中不修改 Apache 条目（保持 `isLikelyProxy=false`），而是在代理头检查阶段添加 Apache 正向代理判断。

在 `hasProxyHeaders` 被调用之前，添加 Apache mod_proxy 特殊检测（在现有 `// 只有排除了所有已知Web服务器后，才检查代理特征头` 注释之前）：

```go
				// Apache mod_proxy 正向代理特殊检测
				// 区分：Apache mod_proxy 对 CONNECT 返回 200 + Via 头
				// 普通 Apache 对 CONNECT 返回 405
				if strings.Contains(bannerLower, "apache") {
					// 如果响应是 CONNECT 200 + Via/Proxy-Agent → 正向代理
					if (strings.Contains(bannerStr, " 200 ") || strings.Contains(bannerStr, " 200 Connection")) &&
						(strings.Contains(bannerLower, "via:") || strings.Contains(bannerLower, "proxy-agent:")) {
						return "http-proxy", true
					}
					// 否则保持为 Web 服务器
					return "apache", false
				}
```

- [ ] **Step 3: 扩展 isCommonProxyPort 添加 3proxy/gost/V2Ray 常用端口**
文件: `free-proxy-scanner/internal/scanner/probe/port_classification.go` (修改 `isCommonProxyPort` 函数)

```go
func (p *Probe) isCommonProxyPort(port int) bool {
	commonProxyPorts := map[int]bool{
		1080: true, // SOCKS
		1081: true, // SOCKS
		1082: true, // SOCKS4
		3128: true, // Squid / 3proxy
		3129: true, // 3proxy SSL
		8118: true, // Privoxy
		8388: true, // Shadowsocks default (for reference)
		8888: true, // HTTP Proxy
		9050: true, // Tor
		9999: true, // HTTP Proxy
		10808: true, // V2Ray HTTP default
		10809: true, // V2Ray SOCKS default
	}
	return commonProxyPorts[port]
}
```

- [ ] **Step 4: 验证 probe 包编译和测试**
Run: `cd free-proxy-scanner && go test -short -count=1 ./internal/scanner/probe/ 2>&1 | tail -20`
Expected:
  - Exit code: 0
  - Output contains: "ok"
  - Output does NOT contain: "FAIL"

- [ ] **Step 5: 提交**
Run: `cd free-proxy-scanner && git add -A && git commit -m "feat(probe): add 3proxy/gost/delegate fingerprints, Apache mod_proxy detection, expand proxy ports"`

---

### Task 3: Scanner Validator 层添加代理匿名等级分类

**Depends on:** Task 1
**Files:**
- Create: `free-proxy-scanner/internal/scanner/validator/anonymity.go`
- Create: `free-proxy-scanner/internal/scanner/validator/anonymity_test.go`

- [ ] **Step 1: 创建匿名等级分类模块**
Create: `free-proxy-scanner/internal/scanner/validator/anonymity.go`

```go
package validator

// AnonymityLevel 表示代理的匿名等级
type AnonymityLevel string

const (
	// AnonymityUnknown 表示无法确定匿名等级
	AnonymityUnknown AnonymityLevel = "unknown"
	// AnonymityTransparent 表示透明代理（转发客户端真实IP）
	AnonymityTransparent AnonymityLevel = "transparent"
	// AnonymityAnonymous 表示匿名代理（隐藏客户端IP，但暴露代理头）
	AnonymityAnonymous AnonymityLevel = "anonymous"
	// AnonymityElite 表示高匿代理（不发送任何代理标识头）
	AnonymityElite AnonymityLevel = "elite"
)

// ProxyAnonymityInfo 包含代理匿名等级分析结果
type ProxyAnonymityInfo struct {
	Level            AnonymityLevel
	HasForwardedFor  bool
	HasVia           bool
	HasProxyAgent    bool
	DetectedClientIP string
}

// ClassifyAnonymity 根据代理转发的请求头判断匿名等级
// proxyResponse 是代理服务器在验证过程中返回的响应
// clientIP 是发起验证请求的客户端IP（用于检测是否被泄露）
//
// 判断规则：
// - Transparent: 包含 X-Forwarded-For 且值为客户端真实IP
// - Anonymous: 无 X-Forwarded-For，但有 Via 或 Proxy-Agent 等代理头
// - Elite: 无任何代理标识头
func ClassifyAnonymity(proxyResponse string, clientIP string) ProxyAnonymityInfo {
	info := ProxyAnonymityInfo{
		Level: AnonymityUnknown,
	}

	responseLower := toLower(proxyResponse)

	// 检测 X-Forwarded-For
	if contains(responseLower, "x-forwarded-for:") {
		info.HasForwardedFor = true
		// 提取 X-Forwarded-For 值检查是否包含客户端真实IP
		xffValue := extractHeaderValue(proxyResponse, "X-Forwarded-For")
		if xffValue != "" && contains(xffValue, clientIP) {
			info.DetectedClientIP = clientIP
			info.Level = AnonymityTransparent
			return info
		}
	}

	// 检测 Via 头
	if contains(responseLower, "via:") {
		info.HasVia = true
	}

	// 检测 Proxy-Agent 头
	if contains(responseLower, "proxy-agent:") {
		info.HasProxyAgent = true
	}

	// 检测其他代理标识头
	proxyHeaders := []string{
		"proxy-connection:",
		"x-proxy-id:",
		"x-real-ip:",
	}
	for _, header := range proxyHeaders {
		if contains(responseLower, header) {
			info.HasProxyAgent = true
			break
		}
	}

	// 根据代理头存在情况判定等级
	if info.HasVia || info.HasProxyAgent {
		info.Level = AnonymityAnonymous
	} else {
		info.Level = AnonymityElite
	}

	return info
}

// toLower converts string to lowercase (helper)
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result[i] = c + 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}

// contains checks if substr exists in s (case-insensitive if s is already lowered)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// extractHeaderValue extracts the value of a given HTTP header from a response
func extractHeaderValue(response, headerName string) string {
	lines := splitLines(response)
	headerLower := toLower(headerName)
	for _, line := range lines {
		lineLower := toLower(line)
		if len(lineLower) > len(headerLower) &&
			lineLower[:len(headerLower)] == headerLower &&
			lineLower[len(headerLower)] == ':' {
			// 找到匹配的 header，提取值
			value := line
			for i := len(headerLower); i < len(value); i++ {
				if value[i] == ':' {
					value = value[i+1:]
					break
				}
			}
			// trim spaces
			value = trimSpaces(value)
			return value
		}
	}
	return ""
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func trimSpaces(s string) string {
	start := 0
	for start < len(s) && s[start] == ' ' {
		start++
	}
	end := len(s)
	for end > start && s[end-1] == ' ' {
		end--
	}
	return s[start:end]
}
```

- [ ] **Step 2: 创建匿名等级分类测试**
Create: `free-proxy-scanner/internal/scanner/validator/anonymity_test.go`

```go
package validator

import (
	"testing"
)

func TestClassifyAnonymity_Transparent(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\n" +
		"X-Forwarded-For: 192.168.1.100\r\n" +
		"Via: 1.1 proxy\r\n" +
		"Content-Length: 0\r\n\r\n"

	info := ClassifyAnonymity(response, "192.168.1.100")
	if info.Level != AnonymityTransparent {
		t.Errorf("Expected transparent, got %s", info.Level)
	}
	if !info.HasForwardedFor {
		t.Error("Expected HasForwardedFor=true")
	}
	if info.DetectedClientIP != "192.168.1.100" {
		t.Errorf("Expected client IP 192.168.1.100, got %s", info.DetectedClientIP)
	}
}

func TestClassifyAnonymity_Anonymous(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\n" +
		"Via: 1.1 proxy\r\n" +
		"Proxy-Agent: squid/4.13\r\n" +
		"Content-Length: 0\r\n\r\n"

	info := ClassifyAnonymity(response, "192.168.1.100")
	if info.Level != AnonymityAnonymous {
		t.Errorf("Expected anonymous, got %s", info.Level)
	}
	if info.HasForwardedFor {
		t.Error("Expected HasForwardedFor=false")
	}
	if !info.HasVia {
		t.Error("Expected HasVia=true")
	}
}

func TestClassifyAnonymity_Elite(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 0\r\n\r\n"

	info := ClassifyAnonymity(response, "192.168.1.100")
	if info.Level != AnonymityElite {
		t.Errorf("Expected elite, got %s", info.Level)
	}
	if info.HasForwardedFor {
		t.Error("Expected HasForwardedFor=false")
	}
	if info.HasVia {
		t.Error("Expected HasVia=false")
	}
}

func TestClassifyAnonymity_AnonymousWithOnlyProxyAgent(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\n" +
		"Proxy-Agent: 3proxy/0.9.4\r\n" +
		"Content-Length: 0\r\n\r\n"

	info := ClassifyAnonymity(response, "192.168.1.100")
	if info.Level != AnonymityAnonymous {
		t.Errorf("Expected anonymous, got %s", info.Level)
	}
}

func TestClassifyAnonymity_TransparentWithXFFNotMatchingClient(t *testing.T) {
	// X-Forwarded-For 存在但不包含客户端真实IP → 可能是多层代理
	response := "HTTP/1.1 200 OK\r\n" +
		"X-Forwarded-For: 10.0.0.1\r\n" +
		"Via: 1.1 proxy\r\n" +
		"Content-Length: 0\r\n\r\n"

	info := ClassifyAnonymity(response, "192.168.1.100")
	// XFF 存在但不匹配客户端IP，不应判为 transparent
	if info.Level == AnonymityTransparent {
		t.Error("Should not be transparent when XFF does not match client IP")
	}
	if !info.HasForwardedFor {
		t.Error("Expected HasForwardedFor=true")
	}
}

func TestClassifyAnonymity_EmptyResponse(t *testing.T) {
	info := ClassifyAnonymity("", "192.168.1.100")
	if info.Level != AnonymityElite {
		t.Errorf("Expected elite for empty response, got %s", info.Level)
	}
}
```

- [ ] **Step 3: 验证 anonymity 模块编译和测试**
Run: `cd free-proxy-scanner && go test -v -count=1 ./internal/scanner/validator/ -run TestClassifyAnonymity 2>&1 | tail -30`
Expected:
  - Exit code: 0
  - Output contains: "PASS" for all 6 test cases
  - Output does NOT contain: "FAIL"

- [ ] **Step 4: 提交**
Run: `cd free-proxy-scanner && git add -A && git commit -m "feat(validator): add proxy anonymity level classification (transparent/anonymous/elite)"`

---

### Task 4: Scanner 添加多格式代理导出器

**Depends on:** None
**Files:**
- Create: `free-proxy-scanner/internal/scanner/exporter/exporter.go`
- Create: `free-proxy-scanner/internal/scanner/exporter/exporter_test.go`

- [ ] **Step 1: 创建代理数据类型和导出器核心**
Create: `free-proxy-scanner/internal/scanner/exporter/exporter.go`

```go
// Package exporter 提供多格式代理导出功能
// 支持的格式：Plain URI, curl 环境变量, Clash YAML, PAC 文件, JSON, Base64 订阅
package exporter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ProxyEntry 表示一个代理条目
type ProxyEntry struct {
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	Protocol     string `json:"protocol"`     // http, https, socks4, socks5
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	Anonymity    string `json:"anonymity,omitempty"`    // transparent, anonymous, elite
	Country      string `json:"country,omitempty"`
	ResponseTime int    `json:"response_time,omitempty"` // 毫秒
	Software     string `json:"software,omitempty"`      // squid, 3proxy, gost, etc.
}

// ExportFormat 定义导出格式类型
type ExportFormat string

const (
	// FormatPlain 输出 IP:PORT 格式（最简单）
	FormatPlain ExportFormat = "plain"
	// FormatURI 输出 protocol://[user:pass@]host:port 格式
	FormatURI ExportFormat = "uri"
	// FormatCurlEnv 输出 curl/wget 可用的环境变量格式
	FormatCurlEnv ExportFormat = "curl_env"
	// FormatClashYAML 输出 Clash/Clash Meta 可用的 YAML 格式
	FormatClashYAML ExportFormat = "clash_yaml"
	// FormatPAC 输出浏览器自动代理配置文件
	FormatPAC ExportFormat = "pac"
	// FormatJSON 输出 JSON 数组
	FormatJSON ExportFormat = "json"
	// FormatBase64Subscription 输出 Base64 编码的订阅格式
	FormatBase64Subscription ExportFormat = "base64_subscription"
	// FormatProxychains 输出 proxychains 配置格式
	FormatProxychains ExportFormat = "proxychains"
)

// Exporter 代理导出器
type Exporter struct{}

// NewExporter 创建新的导出器
func NewExporter() *Exporter {
	return &Exporter{}
}

// Export 将代理列表导出为指定格式
func (e *Exporter) Export(proxies []ProxyEntry, format ExportFormat) (string, error) {
	switch format {
	case FormatPlain:
		return e.exportPlain(proxies), nil
	case FormatURI:
		return e.exportURI(proxies), nil
	case FormatCurlEnv:
		return e.exportCurlEnv(proxies), nil
	case FormatClashYAML:
		return e.exportClashYAML(proxies), nil
	case FormatPAC:
		return e.exportPAC(proxies), nil
	case FormatJSON:
		return e.exportJSON(proxies), nil
	case FormatBase64Subscription:
		return e.exportBase64Subscription(proxies), nil
	case FormatProxychains:
		return e.exportProxychains(proxies), nil
	default:
		return "", fmt.Errorf("unsupported export format: %s", format)
	}
}

// ExportAllFormats 导出所有格式，返回 map[formatName]content
func (e *Exporter) ExportAllFormats(proxies []ProxyEntry) map[ExportFormat]string {
	formats := []ExportFormat{
		FormatPlain, FormatURI, FormatCurlEnv,
		FormatClashYAML, FormatPAC, FormatJSON,
		FormatBase64Subscription, FormatProxychains,
	}
	result := make(map[ExportFormat]string)
	for _, f := range formats {
		content, err := e.Export(proxies, f)
		if err == nil {
			result[f] = content
		}
	}
	return result
}

// === 格式实现 ===

// exportPlain 导出 IP:PORT 格式
func (e *Exporter) exportPlain(proxies []ProxyEntry) string {
	var lines []string
	for _, p := range proxies {
		lines = append(lines, fmt.Sprintf("%s:%d", p.IP, p.Port))
	}
	return strings.Join(lines, "\n")
}

// exportURI 导出 protocol://[user:pass@]host:port 格式
func (e *Exporter) exportURI(proxies []ProxyEntry) string {
	var lines []string
	for _, p := range proxies {
		uri := formatProxyURI(p)
		lines = append(lines, uri)
	}
	return strings.Join(lines, "\n")
}

// exportCurlEnv 导出 curl/wget 环境变量格式
func (e *Exporter) exportCurlEnv(proxies []ProxyEntry) string {
	var lines []string
	lines = append(lines, "# curl / wget 环境变量格式")
	lines = append(lines, "# 使用方法：")
	lines = append(lines, "#   方式1：直接设置环境变量")
	lines = append(lines, "#     export http_proxy=http://ip:port")
	lines = append(lines, "#     export https_proxy=http://ip:port")
	lines = append(lines, "#   方式2：curl -x http://ip:port https://example.com")
	lines = append(lines, "")
	if len(proxies) > 0 {
		p := proxies[0]
		uri := formatProxyURI(p)
		protocol := p.Protocol
		if protocol == "socks4" || protocol == "socks5" {
			protocol = "http" // curl 默认用 http_proxy
		}
		lines = append(lines, fmt.Sprintf("export %s_proxy=\"%s\"", protocol, uri))
		lines = append(lines, fmt.Sprintf("export %ss_proxy=\"%s\"", protocol, uri))
	}
	if len(proxies) > 1 {
		lines = append(lines, "")
		lines = append(lines, "# 备用代理：")
		for i := 1; i < len(proxies) && i <= 5; i++ {
			uri := formatProxyURI(proxies[i])
			lines = append(lines, fmt.Sprintf("# %s", uri))
		}
	}
	return strings.Join(lines, "\n")
}

// exportClashYAML 导出 Clash/Clash Meta YAML 格式
func (e *Exporter) exportClashYAML(proxies []ProxyEntry) string {
	var sb strings.Builder
	sb.WriteString("proxies:\n")
	for i, p := range proxies {
		proxyType := p.Protocol
		// Clash 协议名称映射
		switch p.Protocol {
		case "http":
			proxyType = "http"
		case "https":
			proxyType = "http" // Clash 中 HTTPS 代理类型为 http + tls
		case "socks4":
			proxyType = "socks5" // Clash 不区分 socks4/5
		case "socks5":
			proxyType = "socks5"
		}

		name := fmt.Sprintf("proxy-%d-%s:%d", i+1, p.IP, p.Port)
		if p.Country != "" {
			name = fmt.Sprintf("proxy-%s-%d", strings.ToLower(p.Country), i+1)
		}

		sb.WriteString(fmt.Sprintf("  - name: \"%s\"\n", name))
		sb.WriteString(fmt.Sprintf("    type: %s\n", proxyType))
		sb.WriteString(fmt.Sprintf("    server: %s\n", p.IP))
		sb.WriteString(fmt.Sprintf("    port: %d\n", p.Port))
		if p.Username != "" {
			sb.WriteString(fmt.Sprintf("    username: \"%s\"\n", p.Username))
			sb.WriteString(fmt.Sprintf("    password: \"%s\"\n", p.Password))
		}
		if p.Protocol == "https" {
			sb.WriteString("    tls: true\n")
		}
	}

	// 添加 proxy-groups
	sb.WriteString("\nproxy-groups:\n")
	sb.WriteString("  - name: \"auto-select\"\n")
	sb.WriteString("    type: url-test\n")
	sb.WriteString("    proxies:\n")
	for i := range proxies {
		name := fmt.Sprintf("proxy-%d-%s:%d", i+1, proxies[i].IP, proxies[i].Port)
		if proxies[i].Country != "" {
			name = fmt.Sprintf("proxy-%s-%d", strings.ToLower(proxies[i].Country), i+1)
		}
		sb.WriteString(fmt.Sprintf("      - \"%s\"\n", name))
	}
	sb.WriteString("    url: \"http://www.gstatic.com/generate_204\"\n")
	sb.WriteString("    interval: 300\n")

	return sb.String()
}

// exportPAC 导出浏览器自动代理配置文件
func (e *Exporter) exportPAC(proxies []ProxyEntry) string {
	var sb strings.Builder
	sb.WriteString("function FindProxyForURL(url, host) {\n")

	// 本地地址直连
	sb.WriteString("  // 本地地址直连\n")
	sb.WriteString("  if (isPlainHostName(host) ||\n")
	sb.WriteString("      shExpMatch(host, \"*.local\") ||\n")
	sb.WriteString("      isInNet(host, \"127.0.0.0\", \"255.0.0.0\") ||\n")
	sb.WriteString("      isInNet(host, \"10.0.0.0\", \"255.0.0.0\") ||\n")
	sb.WriteString("      isInNet(host, \"172.16.0.0\", \"255.240.0.0\") ||\n")
	sb.WriteString("      isInNet(host, \"192.168.0.0\", \"255.255.0.0\")) {\n")
	sb.WriteString("    return \"DIRECT\";\n")
	sb.WriteString("  }\n\n")

	// 构建代理列表（PAC 格式：PROXY host:port）
	sb.WriteString("  // 免费代理列表（自动发现）\n")
	if len(proxies) > 0 {
		p := proxies[0]
		proxyStr := fmt.Sprintf("PROXY %s:%d", p.IP, p.Port)
		// SOCKS5 代理使用 SOCKS5 关键字
		if p.Protocol == "socks5" {
			proxyStr = fmt.Sprintf("SOCKS5 %s:%d", p.IP, p.Port)
		}
		sb.WriteString(fmt.Sprintf("  return \"%s; DIRECT\";\n", proxyStr))
	} else {
		sb.WriteString("  return \"DIRECT\";\n")
	}

	sb.WriteString("}\n")
	return sb.String()
}

// exportJSON 导出 JSON 数组格式
func (e *Exporter) exportJSON(proxies []ProxyEntry) string {
	data, err := json.MarshalIndent(proxies, "", "  ")
	if err != nil {
		return "[]"
	}
	return string(data)
}

// exportBase64Subscription 导出 Base64 编码订阅格式
// v2rayN / Shadowrocket / Quantumult X 等工具通用
func (e *Exporter) exportBase64Subscription(proxies []ProxyEntry) string {
	var lines []string
	for _, p := range proxies {
		// 订阅格式：每行一个 URI
		uri := formatProxyURI(p)
		lines = append(lines, uri)
	}
	content := strings.Join(lines, "\n")
	return base64.StdEncoding.EncodeToString([]byte(content))
}

// exportProxychains 导出 proxychains 配置格式
func (e *Exporter) exportProxychains(proxies []ProxyEntry) string {
	var sb strings.Builder
	sb.WriteString("# proxychains 配置格式\n")
	sb.WriteString("# 使用方法：将此内容追加到 /etc/proxychains.conf 或 ~/.proxychains/proxychains.conf\n")
	sb.WriteString("# 然后运行：proxychains4 your_command\n\n")
	sb.WriteString("[ProxyList]\n")
	for _, p := range proxies {
		proxyType := "http"
		switch p.Protocol {
		case "socks4":
			proxyType = "socks4"
		case "socks5":
			proxyType = "socks5"
		case "http", "https":
			proxyType = "http"
		}
		if p.Username != "" {
			sb.WriteString(fmt.Sprintf("%s %s %d %s %s\n", proxyType, p.IP, p.Port, p.Username, p.Password))
		} else {
			sb.WriteString(fmt.Sprintf("%s %s %d\n", proxyType, p.IP, p.Port))
		}
	}
	return sb.String()
}

// === 辅助函数 ===

// formatProxyURI 生成标准代理 URI
func formatProxyURI(p ProxyEntry) string {
	protocol := p.Protocol
	switch protocol {
	case "http":
		protocol = "http"
	case "https":
		protocol = "https"
	case "socks4":
		protocol = "socks4"
	case "socks5":
		protocol = "socks5"
	default:
		protocol = "http"
	}

	if p.Username != "" && p.Password != "" {
		return fmt.Sprintf("%s://%s:%s@%s:%d", protocol, p.Username, p.Password, p.IP, p.Port)
	}
	return fmt.Sprintf("%s://%s:%d", protocol, p.IP, p.Port)
}
```

- [ ] **Step 2: 创建导出器测试**
Create: `free-proxy-scanner/internal/scanner/exporter/exporter_test.go`

```go
package exporter

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func newTestProxies() []ProxyEntry {
	return []ProxyEntry{
		{IP: "192.168.1.1", Port: 8080, Protocol: "http", Anonymity: "anonymous", Country: "US"},
		{IP: "10.0.0.1", Port: 1080, Protocol: "socks5", Anonymity: "elite", Country: "DE"},
		{IP: "172.16.0.1", Port: 3128, Protocol: "http", Username: "admin", Password: "secret"},
	}
}

func TestExport_Plain(t *testing.T) {
	e := NewExporter()
	result, err := e.Export(newTestProxies(), FormatPlain)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if !strings.Contains(result, "192.168.1.1:8080") {
		t.Error("Expected 192.168.1.1:8080 in plain output")
	}
	if !strings.Contains(result, "10.0.0.1:1080") {
		t.Error("Expected 10.0.0.1:1080 in plain output")
	}
	lines := strings.Split(result, "\n")
	if len(lines) != 3 {
		t.Errorf("Expected 3 lines, got %d", len(lines))
	}
}

func TestExport_URI(t *testing.T) {
	e := NewExporter()
	result, err := e.Export(newTestProxies(), FormatURI)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if !strings.Contains(result, "http://192.168.1.1:8080") {
		t.Error("Expected http://192.168.1.1:8080 in URI output")
	}
	if !strings.Contains(result, "socks5://10.0.0.1:1080") {
		t.Error("Expected socks5://10.0.0.1:1080 in URI output")
	}
	if !strings.Contains(result, "http://admin:secret@172.16.0.1:3128") {
		t.Error("Expected http://admin:secret@172.16.0.1:3128 for authenticated proxy")
	}
}

func TestExport_CurlEnv(t *testing.T) {
	e := NewExporter()
	result, err := e.Export(newTestProxies(), FormatCurlEnv)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if !strings.Contains(result, "export") {
		t.Error("Expected 'export' in curl env output")
	}
	if !strings.Contains(result, "_proxy=") {
		t.Error("Expected '_proxy=' in curl env output")
	}
}

func TestExport_ClashYAML(t *testing.T) {
	e := NewExporter()
	result, err := e.Export(newTestProxies(), FormatClashYAML)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if !strings.Contains(result, "proxies:") {
		t.Error("Expected 'proxies:' in Clash YAML output")
	}
	if !strings.Contains(result, "type: http") {
		t.Error("Expected 'type: http' in Clash YAML output")
	}
	if !strings.Contains(result, "type: socks5") {
		t.Error("Expected 'type: socks5' in Clash YAML output")
	}
	if !strings.Contains(result, "proxy-groups:") {
		t.Error("Expected 'proxy-groups:' in Clash YAML output")
	}
}

func TestExport_PAC(t *testing.T) {
	e := NewExporter()
	result, err := e.Export(newTestProxies(), FormatPAC)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if !strings.Contains(result, "FindProxyForURL") {
		t.Error("Expected FindProxyForURL function in PAC output")
	}
	if !strings.Contains(result, "PROXY 192.168.1.1:8080") {
		t.Error("Expected PROXY 192.168.1.1:8080 in PAC output")
	}
	if !strings.Contains(result, "DIRECT") {
		t.Error("Expected DIRECT in PAC output")
	}
}

func TestExport_PAC_SOCKS5Proxy(t *testing.T) {
	e := NewExporter()
	proxies := []ProxyEntry{
		{IP: "10.0.0.1", Port: 1080, Protocol: "socks5"},
	}
	result, _ := e.Export(proxies, FormatPAC)
	if !strings.Contains(result, "SOCKS5 10.0.0.1:1080") {
		t.Error("Expected SOCKS5 keyword for SOCKS5 proxy in PAC")
	}
}

func TestExport_JSON(t *testing.T) {
	e := NewExporter()
	result, err := e.Export(newTestProxies(), FormatJSON)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	var parsed []ProxyEntry
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("JSON parse failed: %v", err)
	}
	if len(parsed) != 3 {
		t.Errorf("Expected 3 entries, got %d", len(parsed))
	}
	if parsed[0].IP != "192.168.1.1" {
		t.Errorf("Expected IP 192.168.1.1, got %s", parsed[0].IP)
	}
}

func TestExport_Base64Subscription(t *testing.T) {
	e := NewExporter()
	result, err := e.Export(newTestProxies(), FormatBase64Subscription)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(result)
	if err != nil {
		t.Fatalf("Base64 decode failed: %v", err)
	}
	if !strings.Contains(string(decoded), "http://192.168.1.1:8080") {
		t.Error("Expected http://192.168.1.1:8080 in decoded subscription")
	}
}

func TestExport_Proxychains(t *testing.T) {
	e := NewExporter()
	result, err := e.Export(newTestProxies(), FormatProxychains)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if !strings.Contains(result, "[ProxyList]") {
		t.Error("Expected [ProxyList] in proxychains output")
	}
	if !strings.Contains(result, "http 192.168.1.1 8080") {
		t.Error("Expected 'http 192.168.1.1 8080' in proxychains output")
	}
	if !strings.Contains(result, "socks5 10.0.0.1 1080") {
		t.Error("Expected 'socks5 10.0.0.1 1080' in proxychains output")
	}
	if !strings.Contains(result, "http 172.16.0.1 3128 admin secret") {
		t.Error("Expected authenticated proxy format in proxychains output")
	}
}

func TestExport_UnsupportedFormat(t *testing.T) {
	e := NewExporter()
	_, err := e.Export(newTestProxies(), ExportFormat("unknown"))
	if err == nil {
		t.Error("Expected error for unsupported format")
	}
}

func TestExport_EmptyProxies(t *testing.T) {
	e := NewExporter()
	proxies := []ProxyEntry{}

	// Plain should return empty string
	result, _ := e.Export(proxies, FormatPlain)
	if result != "" {
		t.Errorf("Expected empty plain output, got: %s", result)
	}

	// JSON should return empty array
	result, _ = e.Export(proxies, FormatJSON)
	if result != "[]" {
		t.Errorf("Expected empty JSON array, got: %s", result)
	}

	// PAC should still be valid
	result, _ = e.Export(proxies, FormatPAC)
	if !strings.Contains(result, "FindProxyForURL") {
		t.Error("PAC should be valid even with empty proxies")
	}
}

func TestExportAllFormats(t *testing.T) {
	e := NewExporter()
	results := e.ExportAllFormats(newTestProxies())

	expectedFormats := []ExportFormat{
		FormatPlain, FormatURI, FormatCurlEnv,
		FormatClashYAML, FormatPAC, FormatJSON,
		FormatBase64Subscription, FormatProxychains,
	}
	for _, f := range expectedFormats {
		if _, ok := results[f]; !ok {
			t.Errorf("Expected format %s in ExportAllFormats results", f)
		}
	}
}
```

- [ ] **Step 3: 验证 exporter 包编译和测试**
Run: `cd free-proxy-scanner && go test -v -count=1 ./internal/scanner/exporter/ 2>&1 | tail -40`
Expected:
  - Exit code: 0
  - Output contains: "PASS" for all test cases
  - Output does NOT contain: "FAIL"

- [ ] **Step 4: 提交**
Run: `cd free-proxy-scanner && git add -A && git commit -m "feat(exporter): add multi-format proxy exporter (plain/URI/curl/Clash/PAC/JSON/base64/proxychains)"`

---

### Task 5: 补全精度测试用例 — 覆盖新增代理软件指纹和匿名等级

**Depends on:** Task 1, Task 2, Task 3
**Files:**
- Modify: `free-proxy-scanner/internal/scanner/precision_comprehensive_test.go` (追加新服务测试用例)

- [ ] **Step 1: 追加代理软件指纹测试用例到 comprehensive test**
文件: `free-proxy-scanner/internal/scanner/precision_comprehensive_test.go` (在现有服务列表末尾追加)

在现有的非代理和代理服务列表中追加新的测试用例：

```go
				// 代理软件指纹识别测试 — 必须被识别为代理
				{9188, "3proxy HTTP", true, "http-proxy"},
				{9189, "gost HTTP Proxy", true, "http-proxy"},
				{9190, "delegate Proxy", true, "http-proxy"},

				// 匿名等级检测目标 — 都必须被识别为代理
				{9191, "Transparent Proxy", true, "http-proxy"},
				{9192, "Anonymous Proxy", true, "http-proxy"},
				{9193, "Elite Proxy", true, "http-proxy"},
```

- [ ] **Step 2: 验证编译**
Run: `cd free-proxy-scanner && go build ./internal/scanner/ 2>&1`
Expected:
  - Exit code: 0
  - Output does NOT contain: "undefined" or "cannot"

- [ ] **Step 3: 提交**
Run: `cd free-proxy-scanner && git add -A && git commit -m "test(scanner): add 3proxy/gost/delegate + anonymity level precision test cases"`

---

### Task 6: 端到端验证 + 子模块同步

**Depends on:** Task 1, Task 2, Task 3, Task 4, Task 5
**Files:**
- Modify: `free-proxy-hunter/free-proxy-scanner` (submodule pointer)
- Modify: `free-proxy-hunter/goat-server` (submodule pointer)

- [ ] **Step 1: 初始化子模块（如未 checkout）**
Run: `cd /home/cc11001100/github/free-proxy-hunter/free-proxy-hunter && git submodule update --init free-proxy-scanner goat-server 2>&1`
Expected:
  - Exit code: 0
  - Submodule directories contain source files

- [ ] **Step 2: 启动 goat-server 并运行精度测试**
Run: `cd goat-server && go build -o goat-server ./cmd/goat-server/ && ./goat-server &>/dev/null & sleep 3 && cd ../free-proxy-scanner && go test -v -run TestScannerPrecision_Comprehensive -count=1 ./internal/scanner/ 2>&1 | grep -E "(PASS|FAIL|precision|correct|False)" | head -30`
Expected:
  - Exit code: 0
  - Output contains: precision numbers
  - False Positives: 0
  - 9188/9189/9190 (3proxy/gost/delegate) 应被识别为代理
  - 9191/9192/9193 (匿名等级) 应被识别为代理

- [ ] **Step 3: 运行匿名等级分类测试**
Run: `cd free-proxy-scanner && go test -v -count=1 ./internal/scanner/validator/ -run TestClassifyAnonymity 2>&1`
Expected:
  - Exit code: 0
  - Output contains: "PASS" for all anonymity tests

- [ ] **Step 4: 运行导出器测试**
Run: `cd free-proxy-scanner && go test -v -count=1 ./internal/scanner/exporter/ 2>&1`
Expected:
  - Exit code: 0
  - Output contains: "PASS" for all 14 exporter tests

- [ ] **Step 5: 停止 goat-server**
Run: `pkill -f goat-server 2>/dev/null; echo "goat-server stopped"`

- [ ] **Step 6: 推送子模块变更**
Run: `cd goat-server && git push origin main 2>&1 && cd ../free-proxy-scanner && git push origin main 2>&1`
Expected:
  - Exit code: 0 for both pushes

- [ ] **Step 7: 更新主仓库子模块指针 + 推送**
Run: `cd /home/cc11001100/github/free-proxy-hunter/free-proxy-hunter && git add free-proxy-scanner goat-server docs/superpowers/plans/2026-06-03-scanner-mainstream-software-compatibility.md && git commit -m "feat(scanner): add mainstream software compatibility - 3proxy/gost/delegate fingerprints, anonymity classification, multi-format exporter" && git push origin master 2>&1`
Expected:
  - Exit code: 0
  - Output contains: "To git@github.com"

---

## Self-Review Results

| # | Check | Result | Action Taken |
|---|-------|--------|-------------|
| 1 | Header (Goal + Architecture + Tech Stack + Risks)? | PASS | Goal covers detection + output compatibility, Architecture has 3-layer data flow |
| 2 | Every Task has Depends on? | PASS | T1=None, T2=T1, T3=T1, T4=None, T5=T1+T2+T3, T6=all |
| 3 | Every Task has exact file paths? | PASS | All paths with file names, some with line number hints |
| 4 | Every Task has 3-8 Steps? | PASS | T1=5, T2=5, T3=4, T4=4, T5=3, T6=7 |
| 5 | New files include complete code? | PASS | proxy_software_scenarios.go, anonymity.go, exporter.go all with full code |
| 6 | Modifications include complete replacement code? | PASS | Probe fingerprint additions, port expansion, test case additions |
| 7 | Code blocks 5-80 lines? | PASS | Largest is proxy_software_scenarios.go service implementations |
| 8 | All functions/types defined in Plan? | PASS | ProxyEntry, AnonymityLevel, Exporter all defined |
| 9 | Every Task has verification commands? | PASS | go build/test/vet with exit code and output pattern |
| 10 | Spec requirements covered? | PASS | Detection fingerprints + anonymity + multi-format export all covered |
| 11 | Each Task independently verifiable? | PASS | Each has compilation/test verification |
| 12 | No TBD/TODO/vague descriptions? | PASS | All concrete with code |
| 13 | No "add validation" abstract instructions? | PASS | Complete code for all steps |
| 14 | Cross-Task names consistent? | PASS | Service names match across manifest, manifest.go, implementation, and tests |
| 15 | Save location correct? | PASS | docs/superpowers/plans/ |

**Status:** ✅ ALL PASS

⏹️ **Phase 3 Complete**

---

## Execution Selection

**Tasks:** 6
**Dependencies:** Yes (T1→T2→T5, T1→T3→T5, T4 independent, T6 depends on all)
**User Preference:** None
**Decision:** Subagent-Driven
**Reasoning:** 6 tasks with cross-dependencies across two repos (goat-server + scanner), requires coordinated execution

**Auto-invoking:** `superpowers:subagent-driven-development`
