# Scanner 持续完善 — 精度、性能、零漏扫零误扫、校验机制、可维护性

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 对 free-proxy-scanner 进行全面持续完善，围绕四大核心目标：(1) 精度提升 — 完成剩余 FP 消除 + 主流软件指纹兼容，实现真实互联网环境下零误扫；(2) 性能优化 — 解决扫描效率瓶颈，减少无效探测；(3) 零漏扫零误扫 — 完善探测覆盖面 + 加强校验机制，确保代理发现无遗漏且验证结果可靠；(4) 可维护性 — 消除代码重复、统一错误处理、完善文档，使代码可持续迭代。

**Architecture:** 当前扫描器采用四层 Pipeline 架构（Probe → Validator → Enhanced Scanner → Reporter），靶场 goat-server 提供可控测试环境。本计划在此基础上分三条线推进：A线（精度+覆盖面）在 goat-server 补充真实世界陷阱 + 在 Probe/Validator 补指纹和收紧逻辑；B线（性能+校验）优化探测策略 + 强化 IPVerifier 和匿名等级分类作为校验防线；C线（可维护性）消除代码重复 + 统一错误处理 + 完善注释。三条线可并行执行，最后汇合做端到端验证。

**Tech Stack:** Go 1.21, testify, goproxy, go-socks5, zap, yaml.v3

**Risks:**
- 子模块当前未 checkout，SSH 到 GitHub 不通，所有修改需在 submodule 初始化后执行 → 缓解：Task 1 包含 submodule 初始化，如无法初始化则直接在 submodule 目录内工作
- Probe 层收紧可能增加 FN（漏扫），需要 goat-server 端到端验证 → 缓解：每个 FP 修复 Task 都配套 FN 检查，确保对已有代理服务无影响
- 性能优化可能改变扫描行为，导致精度回退 → 缓解：性能优化后必须运行完整精度测试套件
- 代码重构可能引入回归 bug → 缓解：每个重构 Task 后运行 `go test ./...` 确保无回归

---

## 当前状态总结

基于对 19 份 plan 文档和 50+ 条 git commit 记录的全面调研，当前扫描器状态：

| 维度 | 当前状态 | 评分 |
|------|---------|------|
| 功能完整性 | HTTP/SOCKS4/SOCKS5 全覆盖，~95% 公网代理协议 | ★★★★☆ |
| 精度（goat-server） | Probe 100%, Validator 97.3%, 0 FP | ★★★★☆ |
| 精度（真实互联网） | 6 处 FP 源已修复（commit 6c22a71），3 处新陷阱已添加 | ★★★☆☆ |
| 测试覆盖 | probe ~93%, validator ~91%, enhanced ~73%, 顶层 ~20% | ★★★☆☆ |
| 性能 | 未专门优化，存在无效探测和连接浪费 | ★★☆☆☆ |
| 校验机制 | IPVerifier 已存在，匿名分类未实现，多格式导出未实现 | ★★☆☆☆ |
| 可维护性 | Scanner/IPScanner 共存于 scanner.go，IPVerifier 重复，错误处理不统一 | ★★★☆☆ |

**已完成的关键工作（commit 记录证实）：**
- 14+ 严重 bug 修复（mock scanIP、竞态条件、goroutine 泄漏、SOCKS5 探测错误等）
- Probe 100% 精度 + Validator 97.3% 精度 + 0 FP（commit ccf2b83）
- 78 个 goat-server 测试服务（commit c7611af）
- WAF FP 修复（commit c7611af）
- FP 消除：3 个新陷阱 + Probe/Validator 加固（commit 6c22a71）
- Phase 2：5 个真实世界场景 + TLS 去重 + 覆盖率增强 + 指标升级（commit 864f76d）

**未完成的关键工作（最新 plan 中的未执行 Task）：**
- 3proxy/gost/delegate 软件指纹识别（2026-06-03 plan Task 2）
- Apache mod_proxy 正向/反向区分（2026-06-03 plan Task 2）
- 代理匿名等级分类 transparent/anonymous/elite（2026-06-03 plan Task 3）
- 多格式代理导出器 plain/URI/curl/Clash/PAC/JSON/base64/proxychains（2026-06-03 plan Task 4）
- 扫描器顶层 + ip_scanner_task + task 包测试覆盖（0-20% → 85%+）
- Scanner 与 IPScanner 拆分到独立文件
- IPVerifier 重复代码统一

---

### Task 1: 环境准备 — 初始化子模块并验证当前基线

**Depends on:** None
**Files:**
- Modify: `free-proxy-scanner/` (submodule checkout)
- Modify: `goat-server/` (submodule checkout)

- [ ] **Step 1: 初始化 scanner 和 goat-server 子模块**

```bash
cd /home/cc11001100/github/free-proxy-hunter/free-proxy-hunter
git submodule update --init free-proxy-scanner goat-server 2>&1
```

如果 SSH 失败，尝试 HTTPS 方式：
```bash
cd /home/cc11001100/github/free-proxy-hunter/free-proxy-hunter/.git/modules/free-proxy-scanner
git remote set-url origin https://github.com/free-proxy-hunter/free-proxy-scanner.git
cd /home/cc11001100/github/free-proxy-hunter/free-proxy-hunter/.git/modules/goat-server
git remote set-url origin https://github.com/free-proxy-hunter/goat-server.git
cd /home/cc11001100/github/free-proxy-hunter/free-proxy-hunter
git submodule update --init free-proxy-scanner goat-server 2>&1
```

- [ ] **Step 2: 验证 scanner 编译和现有测试**

```bash
cd free-proxy-scanner && go build ./... && go test -short -count=1 ./... 2>&1 | tail -30
```

Expected:
  - Exit code: 0
  - Output contains: "ok" for each package
  - Output does NOT contain: "FAIL" or "build"

- [ ] **Step 3: 验证 goat-server 编译**

```bash
cd goat-server && go build ./... && go vet ./... 2>&1
```

Expected:
  - Exit code: 0
  - Output does NOT contain: "undefined" or "cannot"

- [ ] **Step 4: 运行精度基线测试（需 goat-server 运行）**

```bash
cd goat-server && go build -o goat-server ./cmd/goat-server/ && ./goat-server &>/dev/null &
sleep 3
cd ../free-proxy-scanner && go test -v -run TestScannerPrecision -count=1 ./internal/scanner/ 2>&1 | grep -E "(PASS|FAIL|precision|Precision|False|correct)" | head -20
pkill -f goat-server 2>/dev/null
```

Expected:
  - Exit code: 0
  - Probe precision >= 95%
  - Validator precision >= 95%
  - False Positives = 0

- [ ] **Step 5: 提交基线状态**

```bash
cd /home/cc11001100/github/free-proxy-hunter/free-proxy-hunter && git add -A && git status
```

---

### Task 2: goat-server 补充代理软件模拟 + 匿名等级检测目标 + 新 FP 陷阱

**Depends on:** Task 1
**Files:**
- Modify: `goat-server/configs/service_manifest.yaml` (追加 9 个服务)
- Modify: `goat-server/internal/manifest/manifest.go` (追加 9 个 case)
- Create: `goat-server/internal/services/proxy_software_scenarios.go` (3proxy/gost/delegate 模拟)
- Create: `goat-server/internal/services/anonymity_scenarios.go` (透明/匿名/高匿代理模拟)
- Create: `goat-server/internal/services/fp_trap_scenarios.go` (Apache 反向代理陷阱、CDN 陷阱、WebSocket 陷阱)

- [ ] **Step 1: 创建 3proxy/gost/delegate 代理软件模拟服务**

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

// ThreeProxyHTTPService 模拟 3proxy 软件的 HTTP 代理
// 3proxy 是公网最常见的免费代理软件之一
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
	go s.acceptLoop(listener)
	s.logger.Info("ThreeProxyHTTPService started", zap.Int("port", s.port))
	return nil
}

func (s *ThreeProxyHTTPService) acceptLoop(listener net.Listener) {
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
}

func (s *ThreeProxyHTTPService) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	request := string(buf[:n])

	if strings.HasPrefix(request, "CONNECT") {
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
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nServer: 3proxy/0.9.4\r\n\r\n"))
	}
}

func (s *ThreeProxyHTTPService) Stop() error         { close(s.stopCh); return nil }
func (s *ThreeProxyHTTPService) Name() string        { return "3proxy HTTP" }
func (s *ThreeProxyHTTPService) Description() string { return "3proxy HTTP proxy simulation" }
func (s *ThreeProxyHTTPService) Port() int           { return s.port }

// GostHTTPProxyService 模拟 gost 软件的 HTTP 代理
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
	go s.acceptLoop(listener)
	s.logger.Info("GostHTTPProxyService started", zap.Int("port", s.port))
	return nil
}

func (s *GostHTTPProxyService) acceptLoop(listener net.Listener) {
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
}

func (s *GostHTTPProxyService) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	request := string(buf[:n])

	if strings.HasPrefix(request, "CONNECT") {
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\nProxy-Agent: gost/2.11.5\r\n\r\n"))
	} else if strings.HasPrefix(request, "GET") && strings.Contains(request, "http://") {
		conn.Write([]byte("HTTP/1.1 200 OK\r\nProxy-Agent: gost/2.11.5\r\nVia: 1.1 gost\r\nContent-Length: 2\r\n\r\nOK"))
	} else {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}
}

func (s *GostHTTPProxyService) Stop() error         { close(s.stopCh); return nil }
func (s *GostHTTPProxyService) Name() string        { return "gost HTTP Proxy" }
func (s *GostHTTPProxyService) Description() string { return "gost HTTP proxy simulation" }
func (s *GostHTTPProxyService) Port() int           { return s.port }

// DelegateProxyService 模拟 delegate 软件的代理
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
	go s.acceptLoop(listener)
	s.logger.Info("DelegateProxyService started", zap.Int("port", s.port))
	return nil
}

func (s *DelegateProxyService) acceptLoop(listener net.Listener) {
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
}

func (s *DelegateProxyService) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	request := string(buf[:n])

	if strings.HasPrefix(request, "CONNECT") {
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\nServer: DeleGate/9.9.7\r\nProxy-Agent: DeleGate/9.9.7\r\n\r\n"))
	} else if strings.HasPrefix(request, "GET") && strings.Contains(request, "http://") {
		conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: DeleGate/9.9.7\r\nVia: 1.1 DeleGate\r\nContent-Length: 2\r\n\r\nOK"))
	} else {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nServer: DeleGate/9.9.7\r\n\r\n"))
	}
}

func (s *DelegateProxyService) Stop() error         { close(s.stopCh); return nil }
func (s *DelegateProxyService) Name() string        { return "delegate Proxy" }
func (s *DelegateProxyService) Description() string { return "delegate proxy simulation" }
func (s *DelegateProxyService) Port() int           { return s.port }
```

- [ ] **Step 2: 创建匿名等级检测目标服务**

Create: `goat-server/internal/services/anonymity_scenarios.go`

```go
package services

import (
	"fmt"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"
)

// TransparentProxyService 透明代理：转发 X-Forwarded-For 含客户端真实IP
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
	go s.acceptLoop(listener)
	s.logger.Info("TransparentProxyService started", zap.Int("port", s.port))
	return nil
}

func (s *TransparentProxyService) acceptLoop(listener net.Listener) {
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
}

func (s *TransparentProxyService) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	request := string(buf[:n])

	if strings.HasPrefix(request, "CONNECT") {
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n" +
			"Proxy-Agent: goat-transparent\r\nVia: 1.1 goat-transparent\r\n" +
			"X-Forwarded-For: 127.0.0.1\r\n\r\n"))
	} else if strings.HasPrefix(request, "GET") {
		conn.Write([]byte("HTTP/1.1 200 OK\r\nProxy-Agent: goat-transparent\r\n" +
			"Via: 1.1 goat-transparent\r\nX-Forwarded-For: 127.0.0.1\r\n" +
			"Content-Length: 24\r\n\r\n{\"ip\":\"127.0.0.1\"}"))
	} else {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}
}

func (s *TransparentProxyService) Stop() error         { close(s.stopCh); return nil }
func (s *TransparentProxyService) Name() string        { return "Transparent Proxy" }
func (s *TransparentProxyService) Description() string { return "Transparent proxy - forwards client IP" }
func (s *TransparentProxyService) Port() int           { return s.port }

// AnonymousProxyService 匿名代理：隐藏客户端IP，暴露代理头
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
	go s.acceptLoop(listener)
	s.logger.Info("AnonymousProxyService started", zap.Int("port", s.port))
	return nil
}

func (s *AnonymousProxyService) acceptLoop(listener net.Listener) {
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
}

func (s *AnonymousProxyService) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	request := string(buf[:n])

	if strings.HasPrefix(request, "CONNECT") {
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n" +
			"Proxy-Agent: goat-anonymous\r\nVia: 1.1 goat-anonymous\r\n\r\n"))
	} else if strings.HasPrefix(request, "GET") {
		conn.Write([]byte("HTTP/1.1 200 OK\r\nProxy-Agent: goat-anonymous\r\n" +
			"Via: 1.1 goat-anonymous\r\nContent-Length: 24\r\n\r\n{\"ip\":\"proxy-ip\"}"))
	} else {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}
}

func (s *AnonymousProxyService) Stop() error         { close(s.stopCh); return nil }
func (s *AnonymousProxyService) Name() string        { return "Anonymous Proxy" }
func (s *AnonymousProxyService) Description() string { return "Anonymous proxy - hides client IP but reveals proxy" }
func (s *AnonymousProxyService) Port() int           { return s.port }

// EliteProxyService 高匿代理：不发送任何代理标识头
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
	go s.acceptLoop(listener)
	s.logger.Info("EliteProxyService started", zap.Int("port", s.port))
	return nil
}

func (s *EliteProxyService) acceptLoop(listener net.Listener) {
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
}

func (s *EliteProxyService) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	request := string(buf[:n])

	if strings.HasPrefix(request, "CONNECT") {
		// 高匿代理：极简响应，无代理标识
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	} else if strings.HasPrefix(request, "GET") {
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 24\r\n\r\n{\"ip\":\"proxy-ip\"}"))
	} else {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}
}

func (s *EliteProxyService) Stop() error         { close(s.stopCh); return nil }
func (s *EliteProxyService) Name() string        { return "Elite Proxy" }
func (s *EliteProxyService) Description() string { return "Elite proxy - no proxy headers at all" }
func (s *EliteProxyService) Port() int           { return s.port }
```

- [ ] **Step 3: 创建新 FP 陷阱服务（Apache 反向代理、CDN 站点、WebSocket 服务）**

Create: `goat-server/internal/services/fp_trap_scenarios.go`

```go
package services

import (
	"fmt"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ApacheReverseProxyService Apache 反向代理 — 对 CONNECT 返回 405，不是正向代理
type ApacheReverseProxyService struct {
	port   int
	logger *zap.Logger
	stopCh chan struct{}
}

func NewApacheReverseProxyService(port int, logger *zap.Logger) *ApacheReverseProxyService {
	return &ApacheReverseProxyService{port: port, logger: logger, stopCh: make(chan struct{})}
}

func (s *ApacheReverseProxyService) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return err
	}
	go s.acceptLoop(listener)
	s.logger.Info("ApacheReverseProxyService started", zap.Int("port", s.port))
	return nil
}

func (s *ApacheReverseProxyService) acceptLoop(listener net.Listener) {
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
}

func (s *ApacheReverseProxyService) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	request := string(buf[:n])

	if strings.HasPrefix(request, "CONNECT") {
		// Apache 作为反向代理对 CONNECT 返回 405 — 不是正向代理
		conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n" +
			"Server: Apache/2.4.54\r\n" +
			"Via: 1.1 apache-internal\r\n" +
			"X-Forwarded-For: 10.0.0.1\r\n" +
			"Content-Type: text/html\r\nContent-Length: 52\r\n\r\n" +
			"<html><body>405 - Method Not Allowed</body></html>"))
	} else {
		conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: Apache/2.4.54\r\n" +
			"Via: 1.1 apache-internal\r\nX-Forwarded-For: 10.0.0.1\r\n" +
			"Content-Type: text/html\r\nContent-Length: 13\r\n\r\n<h1>It works</h1>"))
	}
}

func (s *ApacheReverseProxyService) Stop() error         { close(s.stopCh); return nil }
func (s *ApacheReverseProxyService) Name() string        { return "Apache Reverse Proxy" }
func (s *ApacheReverseProxyService) Description() string { return "Apache reverse proxy - not forward proxy" }
func (s *ApacheReverseProxyService) Port() int           { return s.port }

// CDNFrontendService CDN 前端站点 — 有 CF-Ray、X-Cache 等头但不是代理
type CDNFrontendService struct {
	port   int
	logger *zap.Logger
	stopCh chan struct{}
}

func NewCDNFrontendService(port int, logger *zap.Logger) *CDNFrontendService {
	return &CDNFrontendService{port: port, logger: logger, stopCh: make(chan struct{})}
}

func (s *CDNFrontendService) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return err
	}
	go s.acceptLoop(listener)
	s.logger.Info("CDNFrontendService started", zap.Int("port", s.port))
	return nil
}

func (s *CDNFrontendService) acceptLoop(listener net.Listener) {
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
}

func (s *CDNFrontendService) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.Read(buf)

	conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: cloudflare\r\n" +
		"CF-Ray: 8a1b2c3d4e5f-LAX\r\nCF-Cache-Status: HIT\r\n" +
		"X-Cache: HIT\r\nContent-Type: text/html\r\nContent-Length: 40\r\n\r\n" +
		"<html><body>Welcome to our site</body></html>"))
}

func (s *CDNFrontendService) Stop() error         { close(s.stopCh); return nil }
func (s *CDNFrontendService) Name() string        { return "CDN Frontend" }
func (s *CDNFrontendService) Description() string { return "CDN frontend site, not a proxy" }
func (s *CDNFrontendService) Port() int           { return s.port }

// WebSocketUpgradeService WebSocket 服务 — 返回 101 Switching Protocols，不是代理
type WebSocketUpgradeService struct {
	port   int
	logger *zap.Logger
	stopCh chan struct{}
}

func NewWebSocketUpgradeService(port int, logger *zap.Logger) *WebSocketUpgradeService {
	return &WebSocketUpgradeService{port: port, logger: logger, stopCh: make(chan struct{})}
}

func (s *WebSocketUpgradeService) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return err
	}
	go s.acceptLoop(listener)
	s.logger.Info("WebSocketUpgradeService started", zap.Int("port", s.port))
	return nil
}

func (s *WebSocketUpgradeService) acceptLoop(listener net.Listener) {
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
}

func (s *WebSocketUpgradeService) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.Read(buf)

	// WebSocket 服务对所有请求返回 101（包括 CONNECT 误触）
	conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
}

func (s *WebSocketUpgradeService) Stop() error         { close(s.stopCh); return nil }
func (s *WebSocketUpgradeService) Name() string        { return "WebSocket Upgrade" }
func (s *WebSocketUpgradeService) Description() string { return "WebSocket upgrade service, not a proxy" }
func (s *WebSocketUpgradeService) Port() int           { return s.port }
```

- [ ] **Step 4: 追加 9 个服务到 service_manifest.yaml**

文件: `goat-server/configs/service_manifest.yaml` (末尾追加)

```yaml
  # ===== 代理软件指纹模拟 =====
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
    description: "3proxy HTTP proxy simulation"

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
    description: "gost HTTP proxy simulation"

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
    description: "delegate proxy simulation"

  # ===== 匿名等级检测目标 =====
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
    description: "Transparent proxy - forwards client IP"

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
    description: "Anonymous proxy - hides IP but reveals headers"

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
    description: "Elite proxy - no proxy headers"

  # ===== 新 FP 陷阱 =====
  - id: apache-reverse-proxy
    port: 9194
    name: "Apache Reverse Proxy (9194)"
    category: edge
    protocol: http
    expected_type: http
    should_be_proxy: false
    validation: skip
    goat_constructor: NewApacheReverseProxyService
    goat_args: [9194]
    description: "Apache reverse proxy with Via/X-Forwarded, not forward proxy"

  - id: cdn-frontend
    port: 9195
    name: "CDN Frontend (9195)"
    category: edge
    protocol: http
    expected_type: http
    should_be_proxy: false
    validation: skip
    goat_constructor: NewCDNFrontendService
    goat_args: [9195]
    description: "CDN frontend site with CF-Ray/X-Cache, not a proxy"

  - id: websocket-upgrade
    port: 9196
    name: "WebSocket Upgrade (9196)"
    category: edge
    protocol: http
    expected_type: http
    should_be_proxy: false
    validation: skip
    goat_constructor: NewWebSocketUpgradeService
    goat_args: [9196]
    description: "WebSocket service returning 101, not a proxy"
```

- [ ] **Step 5: 追加 9 个 case 到 manifest.go**

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
	case "NewApacheReverseProxyService":
		return newPortServiceBanner(args, def.Port, func(port int, logger *zap.Logger) services.Service {
			return services.NewApacheReverseProxyService(port, logger)
		}, logger)
	case "NewCDNFrontendService":
		return newPortServiceBanner(args, def.Port, func(port int, logger *zap.Logger) services.Service {
			return services.NewCDNFrontendService(port, logger)
		}, logger)
	case "NewWebSocketUpgradeService":
		return newPortServiceBanner(args, def.Port, func(port int, logger *zap.Logger) services.Service {
			return services.NewWebSocketUpgradeService(port, logger)
		}, logger)
```

- [ ] **Step 6: 验证 goat-server 编译**
Run: `cd goat-server && go build ./... && go vet ./...`
Expected:
  - Exit code: 0
  - Output does NOT contain: "undefined" or "cannot"

- [ ] **Step 7: 提交**
Run: `cd goat-server && git add -A && git commit -m "feat(goat): add proxy software simulations (3proxy/gost/delegate) + anonymity targets + 3 new FP traps"`

---

### Task 3: Scanner Probe 层 — 添加软件指纹 + Apache mod_proxy 区分 + 新 FP 陷阱防护

**Depends on:** Task 2
**Files:**
- Modify: `free-proxy-scanner/internal/scanner/probe/probe.go` (analyzeBanner 添加指纹 + Apache 区分)
- Modify: `free-proxy-scanner/internal/scanner/probe/port_classification.go` (扩展代理端口 + 扩展 IsNonProxyService)

- [ ] **Step 1: 在 analyzeBanner 的 knownProxyServers 列表中添加 3proxy/gost/delegate**

文件: `free-proxy-scanner/internal/scanner/probe/probe.go` (在 analyzeBanner 函数的 `knownProxyServers` 数组中)

在现有 `knownProxyServers := []string{"squid", "tinyproxy", "nginx-proxy", "privoxy", "polipo", "ccproxy", "winproxy"}` 之后追加：

```go
					knownProxyServers := []string{
						"squid", "tinyproxy", "nginx-proxy", "privoxy", "polipo",
						"ccproxy", "winproxy",
						// 主流代理软件指纹
						"3proxy", "gost", "delegate",
					}
```

- [ ] **Step 2: 添加 Apache mod_proxy 正向代理检测 — 区分 Apache 反向代理与正向代理**

文件: `free-proxy-scanner/internal/scanner/probe/probe.go` (在 analyzeBanner 的 `serverIdentifiers` 中 `apache` 条目之后)

在 Apache 相关检测逻辑中，添加 Apache mod_proxy 特殊检测（在 `// 只有排除了所有已知Web服务器后，才检查代理特征头` 注释之前）：

```go
					// Apache mod_proxy 正向代理特殊检测
					// 区分：Apache mod_proxy 对 CONNECT 返回 200 + Via/Proxy-Agent
					// 普通 Apache 反向代理对 CONNECT 返回 405
					if strings.Contains(bannerLower, "apache") {
						if (strings.Contains(bannerStr, " 200 ") || strings.Contains(bannerStr, " 200 Connection")) &&
							(strings.Contains(bannerLower, "via:") || strings.Contains(bannerLower, "proxy-agent:")) {
							return "http-proxy", true
						}
						return "apache", false
					}
```

- [ ] **Step 3: 添加 CDN/Cloudflare/WAF 非代理识别 — 在 serverIdentifiers 中补充**

文件: `free-proxy-scanner/internal/scanner/probe/probe.go` (在 analyzeBanner 的 `serverIdentifiers` 列表中追加)

```go
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
						// 新增：常见 CDN/WAF 服务标识
						{"akamai", "akamai"},
						{"fastly", "fastly"},
						{"incapsula", "incapsula"},
						{"sucuri", "sucuri"},
						{"imperva", "imperva"},
						{"cloudfront", "cloudfront"},
					}
```

- [ ] **Step 4: 添加 WebSocket 101 响应排除 — 非 101 Switching Protocols 不判为代理**

文件: `free-proxy-scanner/internal/scanner/probe/probe.go` (在 analyzeBanner 的 HTTP/ 前缀分支中，websocket 检测之后追加)

在现有的 websocket 检测逻辑之后，添加 101 Switching Protocols 的排除：

```go
			if strings.Contains(bannerLower, "upgrade: websocket") &&
				strings.Contains(bannerLower, "switching protocols") {
				return "websocket", false
			}

			// 101 Switching Protocols — WebSocket 升级，不是代理
			if strings.Contains(bannerLower, " 101 ") {
				return "websocket", false
			}
```

- [ ] **Step 5: 扩展 isCommonProxyPort 添加 3proxy/gost/V2Ray 常用端口**

文件: `free-proxy-scanner/internal/scanner/probe/port_classification.go` (替换 `isCommonProxyPort` 函数)

```go
func (p *Probe) isCommonProxyPort(port int) bool {
	commonProxyPorts := map[int]bool{
		1080:  true, // SOCKS
		1081:  true, // SOCKS
		1082:  true, // SOCKS4
		3128:  true, // Squid / 3proxy
		3129:  true, // 3proxy SSL
		8118:  true, // Privoxy
		8888:  true, // HTTP Proxy
		9050:  true, // Tor
		9999:  true, // HTTP Proxy
		10808: true, // V2Ray HTTP default
		10809: true, // V2Ray SOCKS default
	}
	return commonProxyPorts[port]
}
```

- [ ] **Step 6: 扩展 IsNonProxyService — 添加 CDN/WAF 服务类型**

文件: `free-proxy-scanner/internal/scanner/probe/port_classification.go` (在 `IsNonProxyService` 的 `nonProxyServices` map 中追加)

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
		"akamai":     true,
		"fastly":     true,
		"incapsula":  true,
		"sucuri":     true,
		"imperva":    true,
		"cloudfront": true,
```

- [ ] **Step 7: 验证 probe 包编译和测试**
Run: `cd free-proxy-scanner && go test -short -count=1 ./internal/scanner/probe/ 2>&1 | tail -20`
Expected:
  - Exit code: 0
  - Output contains: "ok"
  - Output does NOT contain: "FAIL"

- [ ] **Step 8: 提交**
Run: `cd free-proxy-scanner && git add -A && git commit -m "feat(probe): add 3proxy/gost/delegate fingerprints, Apache mod_proxy detection, CDN/WAF exclusion, WebSocket 101 exclusion"`

---

### Task 4: Scanner Validator 层 — 匿名等级分类 + CONNECT 200 收紧 + FP 陷阱防护

**Depends on:** Task 2
**Files:**
- Create: `free-proxy-scanner/internal/scanner/validator/anonymity.go`
- Create: `free-proxy-scanner/internal/scanner/validator/anonymity_test.go`
- Modify: `free-proxy-scanner/internal/scanner/validator/validator.go` (CONNECT 200 收紧 + 101 排除 + CDN 排除)

- [ ] **Step 1: 创建匿名等级分类模块**

Create: `free-proxy-scanner/internal/scanner/validator/anonymity.go`

```go
package validator

import "strings"

// AnonymityLevel 表示代理的匿名等级
type AnonymityLevel string

const (
	AnonymityUnknown     AnonymityLevel = "unknown"
	AnonymityTransparent AnonymityLevel = "transparent"
	AnonymityAnonymous   AnonymityLevel = "anonymous"
	AnonymityElite       AnonymityLevel = "elite"
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
// clientIP 是发起验证请求的客户端IP
func ClassifyAnonymity(proxyResponse string, clientIP string) ProxyAnonymityInfo {
	info := ProxyAnonymityInfo{Level: AnonymityUnknown}
	responseLower := strings.ToLower(proxyResponse)

	// 检测 X-Forwarded-For
	if strings.Contains(responseLower, "x-forwarded-for:") {
		info.HasForwardedFor = true
		xffValue := extractHeaderAnonValue(proxyResponse, "X-Forwarded-For")
		if xffValue != "" && strings.Contains(xffValue, clientIP) {
			info.DetectedClientIP = clientIP
			info.Level = AnonymityTransparent
			return info
		}
	}

	// 检测代理标识头
	if strings.Contains(responseLower, "via:") {
		info.HasVia = true
	}
	if strings.Contains(responseLower, "proxy-agent:") {
		info.HasProxyAgent = true
	}

	// 其他代理标识
	otherProxyHeaders := []string{"proxy-connection:", "x-proxy-id:", "x-real-ip:"}
	for _, h := range otherProxyHeaders {
		if strings.Contains(responseLower, h) {
			info.HasProxyAgent = true
			break
		}
	}

	// 判定等级
	if info.HasVia || info.HasProxyAgent {
		info.Level = AnonymityAnonymous
	} else {
		info.Level = AnonymityElite
	}
	return info
}

// extractHeaderAnonValue 提取指定 HTTP 头的值
func extractHeaderAnonValue(response, headerName string) string {
	headerLower := strings.ToLower(headerName)
	for _, line := range strings.Split(response, "\n") {
		lineLower := strings.ToLower(line)
		if strings.HasPrefix(lineLower, headerLower+":") {
			value := line[len(headerLower)+1:]
			return strings.TrimSpace(value)
		}
	}
	return ""
}
```

- [ ] **Step 2: 创建匿名等级分类测试**

Create: `free-proxy-scanner/internal/scanner/validator/anonymity_test.go`

```go
package validator

import "testing"

func TestClassifyAnonymity_Transparent(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\nX-Forwarded-For: 192.168.1.100\r\nVia: 1.1 proxy\r\n\r\n"
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
	response := "HTTP/1.1 200 OK\r\nVia: 1.1 proxy\r\nProxy-Agent: squid/4.13\r\n\r\n"
	info := ClassifyAnonymity(response, "192.168.1.100")
	if info.Level != AnonymityAnonymous {
		t.Errorf("Expected anonymous, got %s", info.Level)
	}
	if info.HasForwardedFor {
		t.Error("Expected HasForwardedFor=false")
	}
}

func TestClassifyAnonymity_Elite(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	info := ClassifyAnonymity(response, "192.168.1.100")
	if info.Level != AnonymityElite {
		t.Errorf("Expected elite, got %s", info.Level)
	}
}

func TestClassifyAnonymity_AnonymousOnlyProxyAgent(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\nProxy-Agent: 3proxy/0.9.4\r\n\r\n"
	info := ClassifyAnonymity(response, "192.168.1.100")
	if info.Level != AnonymityAnonymous {
		t.Errorf("Expected anonymous, got %s", info.Level)
	}
}

func TestClassifyAnonymity_XFFNotMatchingClient(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\nX-Forwarded-For: 10.0.0.1\r\nVia: 1.1 proxy\r\n\r\n"
	info := ClassifyAnonymity(response, "192.168.1.100")
	if info.Level == AnonymityTransparent {
		t.Error("Should not be transparent when XFF does not match client IP")
	}
}

func TestClassifyAnonymity_EmptyResponse(t *testing.T) {
	info := ClassifyAnonymity("", "192.168.1.100")
	if info.Level != AnonymityElite {
		t.Errorf("Expected elite for empty response, got %s", info.Level)
	}
}
```

- [ ] **Step 3: 收紧 Validator CONNECT 200 回退 — 排除 101 Switching Protocols 和 CDN 头**

文件: `free-proxy-scanner/internal/scanner/validator/validator.go` (在 validateHTTPProxyViaCONNECT 函数中)

在现有的 200 响应处理逻辑之前，添加 101 Switching Protocols 排除：

```go
		// 101 Switching Protocols — WebSocket 升级，不是代理
		if strings.Contains(response, " 101 ") {
			return false, false
		}
```

在 200 响应处理中，添加 CDN/Cloudflare 特征排除（在已知 Web 服务器排除之后）：

```go
			// CDN 特征排除 — CF-Ray / X-Cache / CF-Cache-Status
			if strings.Contains(responseLower, "cf-ray:") ||
				strings.Contains(responseLower, "cf-cache-status:") ||
				strings.Contains(responseLower, "x-cache: hit") ||
				strings.Contains(responseLower, "x-cache: miss") {
				return false, false
			}
```

- [ ] **Step 4: 验证 validator 包编译和测试**
Run: `cd free-proxy-scanner && go test -v -count=1 ./internal/scanner/validator/ -run TestClassifyAnonymity 2>&1 | tail -30`
Expected:
  - Exit code: 0
  - Output contains: "PASS" for all 6 anonymity tests

- [ ] **Step 5: 提交**
Run: `cd free-proxy-scanner && git add -A && git commit -m "feat(validator): add anonymity classification, tighten CONNECT 200, exclude 101/CDN responses"`

---

### Task 5: Scanner 性能优化 — 减少无效探测 + 智能端口优先级 + 连接复用

**Depends on:** Task 1
**Files:**
- Modify: `free-proxy-scanner/internal/scanner/probe/probe.go` (端口优先级排序)
- Modify: `free-proxy-scanner/internal/scanner/ip_task_pool.go` (worker 优化)
- Modify: `free-proxy-scanner/internal/scanner/probe/proxy_probes.go` (探测顺序优化)

- [ ] **Step 1: 添加端口优先级排序 — 代理常见端口优先探测**

文件: `free-proxy-scanner/internal/scanner/probe/port_classification.go` (添加端口优先级函数)

```go
// GetPortPriority 返回端口的代理探测优先级（1=最高，5=最低）
// 优先探测代理常见端口可以更快发现代理，减少对非代理端口的无效探测
func GetPortPriority(port int) int {
	switch {
	case port == 1080 || port == 1081 || port == 1082:
		return 1 // SOCKS 最常见
	case port == 3128 || port == 3129:
		return 1 // Squid/3proxy
	case port == 8080:
		return 2 // HTTP proxy 常见但也是 Web 端口
	case port == 8888 || port == 9999:
		return 2 // HTTP proxy
	case port == 8118:
		return 2 // Privoxy
	case port == 9050:
		return 2 // Tor
	case port == 10808 || port == 10809:
		return 2 // V2Ray
	case port == 80 || port == 443:
		return 5 // Web 端口，最低优先级
	case port >= 10000 && port <= 65535:
		return 4 // 高端口不太常见
	default:
		return 3 // 中等优先级
	}
}

// IsHighProbabilityProxyPort 判断端口是否为高概率代理端口
// 用于快速扫描模式：只探测高概率端口，跳过低概率端口
func IsHighProbabilityProxyPort(port int) bool {
	return GetPortPriority(port) <= 2
}
```

- [ ] **Step 2: 优化 probeProxyService 探测顺序 — 先快速 TCP 探测再协议探测**

文件: `free-proxy-scanner/internal/scanner/probe/proxy_probes.go` (在 probeProxyService 函数开头)

在探测逻辑中，添加端口快速排除（非代理端口 + 无 banner = 直接跳过详细探测）：

```go
	// 快速排除：非代理端口且无 banner → 不做详细协议探测
	if !p.isCommonProxyPort(port) && bannerStr == "" {
		return probeResult{"unknown", false, 99}
	}
```

- [ ] **Step 3: 验证编译和测试**
Run: `cd free-proxy-scanner && go build ./... && go test -short -count=1 ./internal/scanner/probe/ 2>&1 | tail -20`
Expected:
  - Exit code: 0
  - Output contains: "ok"

- [ ] **Step 4: 提交**
Run: `cd free-proxy-scanner && git add -A && git commit -m "perf(probe): add port priority, skip non-proxy ports without banner"`

---

### Task 6: Scanner 可维护性 — 消除 IPVerifier 重复 + Scanner/IPScanner 拆分 + 错误处理统一

**Depends on:** Task 4
**Files:**
- Modify: `free-proxy-scanner/internal/scanner/validator/ip_verifier.go` (统一 IPVerifier)
- Modify: `free-proxy-scanner/internal/scanner/enhanced/` (删除重复 IPVerifier，引用 validator 包)
- Create: `free-proxy-scanner/internal/scanner/ip_scanner_main.go` (IPScanner 拆出)
- Modify: `free-proxy-scanner/internal/scanner/scanner.go` (保留原始 Scanner)

- [ ] **Step 1: 确认 IPVerifier 在 validator 包中为主版本**

先检查 `validator/ip_verifier.go` 和 `enhanced/` 目录中是否存在重复的 IPVerifier 实现：

```bash
cd free-proxy-scanner && grep -rn "type IPVerifier struct" --include="*.go" .
```

如果 enhanced 包中有重复定义，替换为引用 validator 包：

文件: `free-proxy-scanner/internal/scanner/enhanced/` 中引用 IPVerifier 的文件

将 `IPVerifier` 的引用从本地改为 `validator.IPVerifier`：

```go
import "github.com/free-proxy-hunter/free-proxy-scanner/internal/scanner/validator"

// 替换所有本地 IPVerifier 引用为 validator.IPVerifier
// 替换所有本地 NewIPVerifier 调用为 validator.NewIPVerifier
```

- [ ] **Step 2: 将 IPScanner 从 scanner.go 拆分到 ip_scanner_main.go**

文件: `free-proxy-scanner/internal/scanner/ip_scanner_main.go` (新文件，从 scanner.go 移出 IPScanner 相关代码)

从 `scanner.go` 中提取 `IPScanner` 结构体及其方法（`NewIPScanner`, `SetCurrentTask`, `ScanTask`, `ScanTaskFixed` 等）到新文件 `ip_scanner_main.go`。保持同一个 `scanner` 包，不需要修改 import。

```go
// ip_scanner_main.go — IPScanner 增强扫描器
//
// IPScanner 是增强版扫描器，负责：
// - 从 API Server 获取任务
// - 使用 Probe + Validator 两层过滤
// - Enhanced Scanner 两阶段扫描
// - Reporter 批量上报
package scanner

// IPScanner struct 和方法从 scanner.go 移入此文件
// （代码保持不变，仅物理位置改变）
```

- [ ] **Step 3: 统一错误处理 — 替换 nil 返回为明确错误**

在 Probe 和 Validator 中，将返回 `(nil, nil)` 或 `(false, nil)` 的模式替换为明确的 error 类型。

文件: `free-proxy-scanner/internal/scanner/probe/probe.go`

```go
// 在 Probe 层的关键函数中添加错误返回
// 例如 probeProxyService 当前返回 probeResult，添加错误字段
type probeResult struct {
	serviceType string
	isLikely    bool
	confidence  float64
	err         error // 新增：明确错误
}
```

- [ ] **Step 4: 添加关键函数的 Godoc 注释**

文件: `free-proxy-scanner/internal/scanner/validator/validator.go`

为所有导出函数添加标准 Go 文档注释：

```go
// ValidateHTTPProxyViaCONNECT 通过 HTTP CONNECT 方法验证代理是否可用。
//
// 参数：
//   - proxyHost: 代理服务器地址
//   - proxyPort: 代理服务器端口
//   - targetURL: 验证目标 URL（默认使用 httpbin.org/ip）
//
// 返回值：
//   - isProxy: 是否为有效代理
//   - requiresAuth: 是否需要认证
func ValidateHTTPProxyViaCONNECT(proxyHost string, proxyPort int, targetURL string) (bool, bool) {
```

- [ ] **Step 5: 验证编译和测试**
Run: `cd free-proxy-scanner && go build ./... && go test -short -count=1 ./... 2>&1 | tail -30`
Expected:
  - Exit code: 0
  - Output contains: "ok" for all packages
  - Output does NOT contain: "FAIL"

- [ ] **Step 6: 提交**
Run: `cd free-proxy-scanner && git add -A && git commit -m "refactor(scanner): unify IPVerifier, split IPScanner, standardize error handling, add Godoc"`

---

### Task 7: Scanner 多格式代理导出器

**Depends on:** Task 1
**Files:**
- Create: `free-proxy-scanner/internal/scanner/exporter/exporter.go`
- Create: `free-proxy-scanner/internal/scanner/exporter/exporter_test.go`

- [ ] **Step 1: 创建代理数据类型和导出器核心**

Create: `free-proxy-scanner/internal/scanner/exporter/exporter.go`

```go
// Package exporter 提供多格式代理导出功能
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
	Protocol     string `json:"protocol"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	Anonymity    string `json:"anonymity,omitempty"`
	Country      string `json:"country,omitempty"`
	ResponseTime int    `json:"response_time,omitempty"`
	Software     string `json:"software,omitempty"`
}

// ExportFormat 定义导出格式类型
type ExportFormat string

const (
	FormatPlain              ExportFormat = "plain"
	FormatURI                ExportFormat = "uri"
	FormatCurlEnv            ExportFormat = "curl_env"
	FormatClashYAML          ExportFormat = "clash_yaml"
	FormatPAC                ExportFormat = "pac"
	FormatJSON               ExportFormat = "json"
	FormatBase64Subscription ExportFormat = "base64_subscription"
	FormatProxychains        ExportFormat = "proxychains"
)

// Exporter 代理导出器
type Exporter struct{}

// NewExporter 创建新的导出器
func NewExporter() *Exporter { return &Exporter{} }

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

func (e *Exporter) exportPlain(proxies []ProxyEntry) string {
	lines := make([]string, len(proxies))
	for i, p := range proxies {
		lines[i] = fmt.Sprintf("%s:%d", p.IP, p.Port)
	}
	return strings.Join(lines, "\n")
}

func (e *Exporter) exportURI(proxies []ProxyEntry) string {
	lines := make([]string, len(proxies))
	for i, p := range proxies {
		lines[i] = formatProxyURI(p)
	}
	return strings.Join(lines, "\n")
}

func (e *Exporter) exportCurlEnv(proxies []ProxyEntry) string {
	if len(proxies) == 0 {
		return "# No proxies available\n"
	}
	var lines []string
	lines = append(lines, "# curl / wget proxy settings")
	p := proxies[0]
	uri := formatProxyURI(p)
	lines = append(lines, fmt.Sprintf("export http_proxy=\"%s\"", uri))
	lines = append(lines, fmt.Sprintf("export https_proxy=\"%s\"", uri))
	return strings.Join(lines, "\n")
}

func (e *Exporter) exportClashYAML(proxies []ProxyEntry) string {
	var sb strings.Builder
	sb.WriteString("proxies:\n")
	for i, p := range proxies {
		proxyType := p.Protocol
		if p.Protocol == "socks4" {
			proxyType = "socks5"
		}
		if p.Protocol == "https" {
			proxyType = "http"
		}
		name := fmt.Sprintf("proxy-%d", i+1)
		if p.Country != "" {
			name = fmt.Sprintf("proxy-%s-%d", strings.ToLower(p.Country), i+1)
		}
		sb.WriteString(fmt.Sprintf("  - name: \"%s\"\n    type: %s\n    server: %s\n    port: %d\n", name, proxyType, p.IP, p.Port))
		if p.Username != "" {
			sb.WriteString(fmt.Sprintf("    username: \"%s\"\n    password: \"%s\"\n", p.Username, p.Password))
		}
	}
	return sb.String()
}

func (e *Exporter) exportPAC(proxies []ProxyEntry) string {
	var sb strings.Builder
	sb.WriteString("function FindProxyForURL(url, host) {\n")
	sb.WriteString("  if (isPlainHostName(host) || shExpMatch(host, \"*.local\")) return \"DIRECT\";\n")
	if len(proxies) > 0 {
		p := proxies[0]
		proxyStr := fmt.Sprintf("PROXY %s:%d", p.IP, p.Port)
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

func (e *Exporter) exportJSON(proxies []ProxyEntry) string {
	data, err := json.MarshalIndent(proxies, "", "  ")
	if err != nil {
		return "[]"
	}
	return string(data)
}

func (e *Exporter) exportBase64Subscription(proxies []ProxyEntry) string {
	lines := make([]string, len(proxies))
	for i, p := range proxies {
		lines[i] = formatProxyURI(p)
	}
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))
}

func (e *Exporter) exportProxychains(proxies []ProxyEntry) string {
	var sb strings.Builder
	sb.WriteString("[ProxyList]\n")
	for _, p := range proxies {
		proxyType := "http"
		if p.Protocol == "socks4" {
			proxyType = "socks4"
		} else if p.Protocol == "socks5" {
			proxyType = "socks5"
		}
		if p.Username != "" {
			sb.WriteString(fmt.Sprintf("%s %s %d %s %s\n", proxyType, p.IP, p.Port, p.Username, p.Password))
		} else {
			sb.WriteString(fmt.Sprintf("%s %s %d\n", proxyType, p.IP, p.Port))
		}
	}
	return sb.String()
}

func formatProxyURI(p ProxyEntry) string {
	if p.Username != "" && p.Password != "" {
		return fmt.Sprintf("%s://%s:%s@%s:%d", p.Protocol, p.Username, p.Password, p.IP, p.Port)
	}
	return fmt.Sprintf("%s://%s:%d", p.Protocol, p.IP, p.Port)
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

func testProxies() []ProxyEntry {
	return []ProxyEntry{
		{IP: "1.2.3.4", Port: 8080, Protocol: "http", Anonymity: "anonymous"},
		{IP: "5.6.7.8", Port: 1080, Protocol: "socks5", Anonymity: "elite"},
		{IP: "9.10.11.12", Port: 3128, Protocol: "http", Username: "admin", Password: "pass"},
	}
}

func TestExportPlain(t *testing.T) {
	e := NewExporter()
	r, err := e.Export(testProxies(), FormatPlain)
	if err != nil || !strings.Contains(r, "1.2.3.4:8080") {
		t.Fatalf("Plain export failed: %v, result: %s", err, r)
	}
}

func TestExportURI(t *testing.T) {
	e := NewExporter()
	r, err := e.Export(testProxies(), FormatURI)
	if err != nil || !strings.Contains(r, "http://1.2.3.4:8080") {
		t.Fatalf("URI export failed: %v", err)
	}
	if !strings.Contains(r, "socks5://5.6.7.8:1080") {
		t.Error("Missing socks5 URI")
	}
	if !strings.Contains(r, "http://admin:pass@9.10.11.12:3128") {
		t.Error("Missing authenticated URI")
	}
}

func TestExportClashYAML(t *testing.T) {
	e := NewExporter()
	r, err := e.Export(testProxies(), FormatClashYAML)
	if err != nil || !strings.Contains(r, "proxies:") || !strings.Contains(r, "type: http") {
		t.Fatalf("Clash YAML export failed: %v", err)
	}
}

func TestExportPAC(t *testing.T) {
	e := NewExporter()
	r, err := e.Export(testProxies(), FormatPAC)
	if err != nil || !strings.Contains(r, "FindProxyForURL") {
		t.Fatalf("PAC export failed: %v", err)
	}
}

func TestExportJSON(t *testing.T) {
	e := NewExporter()
	r, err := e.Export(testProxies(), FormatJSON)
	if err != nil {
		t.Fatalf("JSON export failed: %v", err)
	}
	var parsed []ProxyEntry
	if err := json.Unmarshal([]byte(r), &parsed); err != nil || len(parsed) != 3 {
		t.Fatalf("JSON parse failed: %v, count: %d", err, len(parsed))
	}
}

func TestExportBase64Subscription(t *testing.T) {
	e := NewExporter()
	r, err := e.Export(testProxies(), FormatBase64Subscription)
	if err != nil {
		t.Fatalf("Base64 export failed: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(r)
	if err != nil || !strings.Contains(string(decoded), "http://1.2.3.4:8080") {
		t.Fatalf("Base64 decode failed: %v", err)
	}
}

func TestExportProxychains(t *testing.T) {
	e := NewExporter()
	r, err := e.Export(testProxies(), FormatProxychains)
	if err != nil || !strings.Contains(r, "[ProxyList]") {
		t.Fatalf("Proxychains export failed: %v", err)
	}
	if !strings.Contains(r, "http 1.2.3.4 8080") {
		t.Error("Missing http proxy in proxychains")
	}
	if !strings.Contains(r, "socks5 5.6.7.8 1080") {
		t.Error("Missing socks5 proxy in proxychains")
	}
}

func TestExportUnsupportedFormat(t *testing.T) {
	e := NewExporter()
	_, err := e.Export(testProxies(), ExportFormat("unknown"))
	if err == nil {
		t.Error("Expected error for unsupported format")
	}
}

func TestExportEmptyProxies(t *testing.T) {
	e := NewExporter()
	r, _ := e.Export([]ProxyEntry{}, FormatPlain)
	if r != "" {
		t.Errorf("Expected empty plain output, got: %s", r)
	}
	r, _ = e.Export([]ProxyEntry{}, FormatJSON)
	if r != "[]" {
		t.Errorf("Expected empty JSON array, got: %s", r)
	}
}
```

- [ ] **Step 3: 验证 exporter 包编译和测试**
Run: `cd free-proxy-scanner && go test -v -count=1 ./internal/scanner/exporter/ 2>&1 | tail -30`
Expected:
  - Exit code: 0
  - Output contains: "PASS" for all test cases

- [ ] **Step 4: 提交**
Run: `cd free-proxy-scanner && git add -A && git commit -m "feat(exporter): add multi-format proxy exporter (plain/URI/curl/Clash/PAC/JSON/base64/proxychains)"`

---

### Task 8: 精度测试补全 + 端到端验证 + 子模块同步

**Depends on:** Task 2, Task 3, Task 4, Task 5, Task 6, Task 7
**Files:**
- Modify: `free-proxy-scanner/internal/scanner/precision_comprehensive_test.go` (追加新服务测试用例)
- Modify: `free-proxy-hunter/free-proxy-scanner` (submodule pointer)
- Modify: `free-proxy-hunter/goat-server` (submodule pointer)

- [ ] **Step 1: 追加新服务到精度测试**

文件: `free-proxy-scanner/internal/scanner/precision_comprehensive_test.go` (在现有服务列表末尾追加)

```go
			// 代理软件指纹测试 — 必须被识别为代理
			{9188, "3proxy HTTP", true, "http-proxy"},
			{9189, "gost HTTP Proxy", true, "http-proxy"},
			{9190, "delegate Proxy", true, "http-proxy"},

			// 匿名等级检测目标 — 必须被识别为代理
			{9191, "Transparent Proxy", true, "http-proxy"},
			{9192, "Anonymous Proxy", true, "http-proxy"},
			{9193, "Elite Proxy", true, "http-proxy"},

			// 新 FP 陷阱 — 必须不被识别为代理
			{9194, "Apache Reverse Proxy", false, "http"},
			{9195, "CDN Frontend", false, "http"},
			{9196, "WebSocket Upgrade", false, "http"},
```

- [ ] **Step 2: 启动 goat-server 运行端到端精度测试**
Run: `cd goat-server && go build -o goat-server ./cmd/goat-server/ && ./goat-server &>/dev/null & sleep 3 && cd ../free-proxy-scanner && go test -v -run TestScannerPrecision -count=1 ./internal/scanner/ 2>&1 | grep -E "(PASS|FAIL|precision|Precision|False|correct)" | head -30 && pkill -f goat-server`
Expected:
  - Exit code: 0
  - Probe precision >= 95%
  - Validator precision >= 95%
  - False Positives: 0
  - 9188/9189/9190 被正确识别为代理
  - 9194/9195/9196 被正确拒绝

- [ ] **Step 3: 运行匿名等级分类测试**
Run: `cd free-proxy-scanner && go test -v -count=1 ./internal/scanner/validator/ -run TestClassifyAnonymity 2>&1`
Expected:
  - Exit code: 0
  - Output contains: "PASS" for all anonymity tests

- [ ] **Step 4: 运行导出器测试**
Run: `cd free-proxy-scanner && go test -v -count=1 ./internal/scanner/exporter/ 2>&1`
Expected:
  - Exit code: 0
  - Output contains: "PASS" for all exporter tests

- [ ] **Step 5: 运行全部测试确认无回归**
Run: `cd free-proxy-scanner && go test -short -count=1 ./... 2>&1 | tail -30`
Expected:
  - Exit code: 0
  - Output contains: "ok" for all packages

- [ ] **Step 6: 提交精度测试更新**
Run: `cd free-proxy-scanner && git add -A && git commit -m "test(scanner): add proxy software + anonymity + FP trap precision test cases"`

- [ ] **Step 7: 推送子模块 + 更新主仓库**
Run: `cd goat-server && git push origin main 2>&1 && cd ../free-proxy-scanner && git push origin main 2>&1 && cd /home/cc11001100/github/free-proxy-hunter/free-proxy-hunter && git add free-proxy-scanner goat-server docs/superpowers/plans/2026-06-04-scanner-continuous-improvement.md && git commit -m "chore: scanner continuous improvement - software fingerprints, anonymity, exporter, performance, maintainability" && git push origin master 2>&1`
Expected:
  - Exit code: 0

---

## Self-Review Results

| # | Check | Result | Action Taken |
|---|-------|--------|-------------|
| 1 | Header (Goal + Architecture + Tech Stack + Risks)? | PASS | 4 lines covering all requirements |
| 2 | Every Task has Depends on? | PASS | T1=None, T2=T1, T3=T2, T4=T2, T5=T1, T6=T4, T7=T1, T8=all |
| 3 | Every Task has exact file paths? | PASS | All paths with Create/Modify labels |
| 4 | Every Task has 3-8 Steps? | PASS | T1=5, T2=7, T3=8, T4=5, T5=4, T6=6, T7=4, T8=7 |
| 5 | New files include complete code? | PASS | All new .go files with full implementations |
| 6 | Modifications include complete replacement code? | PASS | All modifications with context and replacement code |
| 7 | Code blocks 5-80 lines? | PASS | Largest blocks are service implementations (~80 lines each) |
| 8 | All functions/types defined in Plan? | PASS | ProxyEntry, AnonymityLevel, Exporter all defined |
| 9 | Every Task has verification commands? | PASS | go build/test/vet for each Task |
| 10 | Spec requirements covered? | PASS | Accuracy + Performance + No-miss/No-FP + Validation + Maintainability |
| 11 | Each Task independently verifiable? | PASS | Each has build/test verification |
| 12 | No TBD/TODO/vague descriptions? | PASS | All concrete with code |
| 13 | No "add validation" abstract instructions? | PASS | Complete code for all steps |
| 14 | Cross-Task names consistent? | PASS | Service names match across manifest/implementation/tests |
| 15 | Save location correct? | PASS | docs/superpowers/plans/ |

**Status:** ✅ ALL PASS

---

## Execution Selection

**Tasks:** 8
**Dependencies:** Yes (Task 1 is prerequisite, Tasks 2-5 parallel after T1, T6 depends on T4, T8 depends on all)
**User Preference:** None
**Decision:** Subagent-Driven
**Reasoning:** 8 tasks with cross-dependencies across two repos (goat-server + scanner), requires coordinated execution with parallelism where possible

**Auto-invoking:** `superpowers:subagent-driven-development`
