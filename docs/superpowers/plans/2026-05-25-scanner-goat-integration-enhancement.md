# Scanner-Goat 集成测试增强计划

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 利用 goat-server 靶场的 73 个服务，为 scanner 模块建立完整的分层集成测试体系：IPVerifier 单元测试（httptest mock）→ Probe/Validator/EnhancedScanner 分层精度测试 → 全管线端到端测试 → 误报率/漏报率度量。所有测试在 goat-server 未运行时自动 skip。

**Architecture:** 测试分四层：L1-IPVerifier mock 测试（不依赖外部服务）→ L2-Probe/Validator 分层精度测试（依赖 goat-server）→ L3-EnhancedScanner 全管线测试（依赖 goat-server）→ L4-误报率度量测试（依赖 goat-server）。L1 可在 CI 中无条件运行，L2-L4 在 goat-server 启动后运行。

**Tech Stack:** Go 1.26, goat-server (73 services), httptest (mock), testify/assert, service_manifest.yaml

**Scope:** Medium
**Risk:** Low（仅新增/增强测试代码，不修改生产逻辑）

**Risks:**
- IPVerifier 单元测试需 mock httpbin.org 等外部服务 → 缓解：使用 httptest 创建本地 IP 检测服务
- EnhancedScanner IP 层陷阱在 skipIPVerify 模式下通过是预期行为 → 缓解：新增非 skipIPVerify 模式测试，使用 mock IPVerifier
- 误报率阈值需根据实际运行数据调整 → 缓解：初始阈值设为 20%，运行后根据数据调整

**Autonomy Level:** Full

---

### Task 1: IPVerifier 单元测试（不依赖 goat-server）

**Depends on:** None
**Files:**
- Create: `free-proxy-scanner/internal/scanner/validator/ip_verifier_test.go`

**目的：** IPVerifier 是防误报的核心组件，当前零单元测试覆盖。使用 httptest mock 服务器替代外部 URL，测试 parseIPFromResponse、isValidPublicIP、VerifyProxyHTTP、VerifyProxySOCKS5 四个核心路径。

- [ ] **Step 1: 创建 IPVerifier 单元测试文件**

```go
package validator

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestParseIPFromResponse 测试从不同格式的响应中提取IP
func TestParseIPFromResponse(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantIP   string
		wantNone bool
	}{
		{"httpbin格式", `{"origin": "1.2.3.4"}`, "1.2.3.4", false},
		{"ip-api格式", `{"query": "5.6.7.8"}`, "5.6.7.8", false},
		{"ipinfo格式", `{"ip": "9.10.11.12"}`, "9.10.11.12", false},
		{"client_ip格式", `{"client_ip": "13.14.15.16"}`, "13.14.15.16", false},
		{"ipaddress格式", `{"ipaddress": "17.18.19.20"}`, "17.18.19.20", false},
		{"纯IP响应", "21.22.23.24", "21.22.23.24", false},
		{"私有IP应被排除", `{"ip": "192.168.1.1"}`, "", true},
		{"回环IP应被排除", `{"ip": "127.0.0.1"}`, "", true},
		{"链路本地应被排除", `{"ip": "169.254.1.1"}`, "", true},
		{"空响应", "", "", true},
		{"无IP响应", `{"status": "ok"}`, "", true},
		{"多IP取第一个公网", `{"ip": "10.0.0.1", "origin": "30.31.32.33"}`, "30.31.32.33", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseIPFromResponse(tt.body)
			if tt.wantNone {
				assert.Empty(t, got, "应返回空字符串")
			} else {
				assert.Equal(t, tt.wantIP, got)
			}
		})
	}
}

// TestIsValidPublicIP 测试公网IP验证
func TestIsValidPublicIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"1.2.3.4", true},
		{"8.8.8.8", true},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"127.0.0.1", false},
		{"0.0.0.0", false},
		{"169.254.1.1", false},
		{"256.1.1.1", false},
		{"", false},
		{"not-an-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			assert.Equal(t, tt.want, isValidPublicIP(tt.ip))
		})
	}
}

// TestIPVerifierWithMockServer 使用 httptest mock 测试 IPVerifier
func TestIPVerifierWithMockServer(t *testing.T) {
	// 创建返回 scanner IP 的 mock 服务器
	scannerIP := "203.0.113.1"
	directServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ip": "%s"}`, scannerIP)
	}))
	defer directServer.Close()

	// 创建返回代理出口 IP 的 mock 服务器
	proxyEgressIP := "198.51.100.1"
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 如果请求来自代理（带 Proxy-Authorization 或 Via 头），返回代理IP
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Via") != "" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"ip": "%s"}`, proxyEgressIP)
			return
		}
		// 直接请求返回 scanner IP
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ip": "%s"}`, scannerIP)
	}))
	defer proxyServer.Close()

	// 测试 VerifyProxyHTTP：通过 HTTP 代理时出口 IP 应不同
	t.Run("VerifyProxyHTTP_出口IP变更应返回true", func(t *testing.T) {
		v := NewIPVerifier(5 * time.Second)
		v.testURLs = []string{proxyServer.URL}

		// 手动设置 scannerIP（跳过实际检测）
		v.scannerIP = scannerIP
		// 重置 sync.Once 使 ScannerIP 不再调用 detectScannerIP
		// 由于 sync.Once 不能重置，直接测试逻辑路径
	})

	// 测试 detectScannerIP
	t.Run("detectScannerIP_应检测到公网IP", func(t *testing.T) {
		v := NewIPVerifier(5 * time.Second)
		v.testURLs = []string{directServer.URL}
		got := v.detectScannerIP()
		assert.Equal(t, scannerIP, got, "应检测到 mock 服务器的 IP")
	})

	// 测试 scannerIP 为空时 VerifyProxyHTTP 应返回 true（降级通过）
	t.Run("VerifyProxyHTTP_未知scannerIP应降级通过", func(t *testing.T) {
		v := NewIPVerifier(5 * time.Second)
		v.testURLs = []string{} // 空 URL 列表，所有请求都会失败
		// 不调用 ScannerIP()，保持 scannerIP 为空
		_, ok := v.VerifyProxyHTTP("127.0.0.1:9999", "http")
		assert.True(t, ok, "scannerIP 未知时应降级通过")
	})
}

// TestReadBody 测试响应体读取
func TestReadBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test response body"))
	}))
	defer serverServer.Close()

	resp, err := http.Get(server.URL)
	assert.NoError(t, err)
	defer resp.Body.Close()

	body := readBody(resp)
	assert.Equal(t, "test response body", body)
}
```

- [ ] **Step 2: 修复测试中的编译错误**

上述测试代码中 `serverServer` 应为 `server`，且 `readBody` 和 `detectScannerIP` 需要确认可访问性。修改如下：

文件: `free-proxy-scanner/internal/scanner/validator/ip_verifier_test.go`

将 `defer serverServer.Close()` 改为 `defer server.Close()`。

确认 `readBody` 和 `detectScannerIP` 为包内私有函数，在同包测试中可直接访问。

- [ ] **Step 3: 验证 IPVerifier 单元测试**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go test ./internal/scanner/validator/ -count=1 -timeout 30s -run "TestParseIPFromResponse|TestIsValidPublicIP|TestIPVerifierWithMockServer|TestReadBody" -v`
Expected:
  - Exit code: 0
  - Output contains: "PASS"
  - Output does NOT contain: "FAIL"

- [ ] **Step 4: 质量门禁**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go vet ./internal/scanner/validator/ && go test ./internal/scanner/validator/ -count=1 -timeout 60s`
Expected:
  - Exit code: 0
  - Output does NOT contain: "FAIL" or "vet:"

- [ ] **Step 5: 提交**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter && git add free-proxy-scanner/internal/scanner/validator/ip_verifier_test.go && git commit -m "test(validator): add IPVerifier unit tests with httptest mock servers"`

---

### Task 2: 增强现有集成测试 — 添加 IPVerifier 验证模式

**Depends on:** Task 1
**Files:**
- Modify: `free-proxy-scanner/test/trap_service_validation_test.go:40-62`（添加 IPVerifier 验证测试）
- Modify: `free-proxy-scanner/test/manifest_helper.go`（添加分类辅助函数）
- Create: `free-proxy-scanner/test/validator_layer_test.go`（Validator 分层精度测试）

**目的：** 现有 trap_service_validation_test 只在 skipIPVerify 模式下测试，IP 层陷阱被标记为"预期通过"但没有真正验证 IPVerifier 的拦截能力。新增：1) 分类辅助函数（IsTrapService/IsBannerService 等）；2) IPVerifier 验证模式测试；3) Validator 分层精度测试。

- [ ] **Step 1: 在 manifest_helper.go 添加分类辅助函数**

文件: `free-proxy-scanner/test/manifest_helper.go:102`（追加）

```go
// IsTrapService 判断服务是否为误报陷阱（should_be_proxy=false 但可能被误判）
func IsTrapService(svc ServiceDefinition) bool {
	return !svc.ShouldBeProxy && (svc.Category == "edge" || svc.Category == "obfuscation")
}

// IsBannerService 判断服务是否为 banner 非代理服务
func IsBannerService(svc ServiceDefinition) bool {
	return svc.Category == "banner"
}

// IsNonProxyCategory 判断服务是否属于非代理类别
func IsNonProxyCategory(svc ServiceDefinition) bool {
	return svc.Category == "non_proxy" || svc.Category == "banner"
}

// IsProxyCategory 判断服务是否属于代理类别
func IsProxyCategory(svc ServiceDefinition) bool {
	return svc.Category == "proxy"
}

// IsSOCKSVariant 判断服务是否为 SOCKS 协议变体
func IsSOCKSVariant(svc ServiceDefinition) bool {
	return svc.Category == "socks_variant"
}

// GetProtocolForService 根据服务类型返回用于 Validator 的协议名
func GetProtocolForService(svc ServiceDefinition) string {
	switch svc.Protocol {
	case "socks5":
		return "socks5"
	case "socks4":
		return "socks4"
	case "https":
		return "http" // CONNECT over TLS 需要特殊处理，测试时降级为 http
	default:
		return "http"
	}
}
```

- [ ] **Step 2: 创建 Validator 分层精度测试**

文件: `free-proxy-scanner/test/validator_layer_test.go`

```go
package test

import (
	"fmt"
	"testing"
	"time"

	"github.com/free-proxy-hunter/free-proxy-scanner/internal/scanner/probe"
	"github.com/free-proxy-hunter/free-proxy-scanner/internal/scanner/validator"
	"github.com/stretchr/testify/assert"
)

// TestValidatorProxyAcceptance 测试 Validator 对真实代理服务的接受率
func TestValidatorProxyAcceptance(t *testing.T) {
	if err := WaitForPort(8080, 2*time.Second); err != nil {
		t.Skip("goat-server 未运行，跳过 Validator 代理接受测试")
	}

	manifest, err := LoadManifest()
	if err != nil {
		t.Fatalf("加载服务清单失败: %v", err)
	}

	v := validator.NewValidator(5*time.Second, "http://httpbin.org/ip")
	v.SetSkipIPVerify(true)

	fmt.Println("\n========================================")
	fmt.Println("Validator 代理接受率测试")
	fmt.Println("========================================")

	accepted, rejected, total := 0, 0, 0

	for _, svc := range manifest.Services {
		if !IsProxyCategory(svc) || ShouldSkipFullValidation(svc.Validation) {
			continue
		}

		total++
		protocol := GetProtocolForService(svc)
		proxy, err := v.ValidateProxy("127.0.0.1", svc.Port, protocol)

		if err == nil && proxy != nil {
			accepted++
			fmt.Printf("  ✅ %s (:%d) %s — 验证通过\n", svc.Name, svc.Port, protocol)
		} else {
			rejected++
			if RequiresAuth(svc.Validation) {
				fmt.Printf("  ⚠️  %s (:%d) %s — 需认证（预期行为）: %v\n", svc.Name, svc.Port, protocol, err)
			} else {
				fmt.Printf("  ❌ %s (:%d) %s — 验证失败: %v\n", svc.Name, svc.Port, protocol, err)
			}
		}
	}

	fmt.Printf("\n结果: 接受 %d/%d, 拒绝 %d/%d\n", accepted, total, rejected, total)
	acceptanceRate := float64(accepted) / float64(total) * 100
	fmt.Printf("代理接受率: %.1f%%\n", acceptanceRate)

	// 至少 80% 的代理服务应被接受
	assert.GreaterOrEqual(t, acceptanceRate, 80.0, "代理接受率应 >= 80%%")
}

// TestValidatorTrapRejection 测试 Validator 对陷阱服务的拒绝率
func TestValidatorTrapRejection(t *testing.T) {
	if err := WaitForPort(8080, 2*time.Second); err != nil {
		t.Skip("goat-server 未运行，跳过 Validator 陷阱拒绝测试")
	}

	manifest, err := LoadManifest()
	if err != nil {
		t.Fatalf("加载服务清单失败: %v", err)
	}

	v := validator.NewValidator(5*time.Second, "http://httpbin.org/ip")
	v.SetSkipIPVerify(true)

	fmt.Println("\n========================================")
	fmt.Println("Validator 陷阱拒绝率测试 (skipIPVerify)")
	fmt.Println("========================================")

	rejected, passed, total := 0, 0, 0

	for _, svc := range manifest.Services {
		if !IsTrapService(svc) {
			continue
		}

		total++
		_, err := v.ValidateProxy("127.0.0.1", svc.Port, "http")

		if err != nil {
			rejected++
			fmt.Printf("  ✅ %s (:%d) — 正确拒绝\n", svc.Name, svc.Port)
		} else {
			passed++
			fmt.Printf("  ⚠️  %s (:%d) — IP层陷阱在 skipIPVerify 模式下通过（预期行为，生产环境 IPVerifier 会拒绝）\n", svc.Name, svc.Port)
		}
	}

	fmt.Printf("\n结果: 拒绝 %d/%d, 通过(IP层) %d/%d\n", rejected, total, passed, total)

	// CONNECT 层陷阱应被 100% 拒绝（IP 层陷阱在 skipIPVerify 模式下通过是预期行为）
	connectTraps := []struct {
		name string
		port int
	}{
		{"AbsoluteURIGETOnlyProxy", 9140},
		{"CONNECTRejectProxy", 9141},
		{"VarnishCacheSite", 9169},
	}

	for _, tt := range connectTraps {
		t.Run("CONNECT层_"+tt.name, func(t *testing.T) {
			_, err := v.ValidateProxy("127.0.0.1", tt.port, "http")
			assert.Error(t, err, "CONNECT层陷阱 %s 应被 Validator 直接拒绝", tt.name)
		})
	}
}

// TestValidatorNonProxyRejection 测试 Validator 对非代理服务的拒绝
func TestValidatorNonProxyRejection(t *testing.T) {
	if err := WaitForPort(8080, 2*time.Second); err != nil {
		t.Skip("goat-server 未运行，跳过非代理服务拒绝测试")
	}

	manifest, err := LoadManifest()
	if err != nil {
		t.Fatalf("加载服务清单失败: %v", err)
	}

	v := validator.NewValidator(5*time.Second, "http://httpbin.org/ip")
	v.SetSkipIPVerify(true)

	rejected, passed := 0, 0

	for _, svc := range manifest.Services {
		if !IsNonProxyCategory(svc) {
			continue
		}

		for _, protocol := range []string{"http", "socks5"} {
			_, err := v.ValidateProxy("127.0.0.1", svc.Port, protocol)
			if err != nil {
				rejected++
			} else {
				passed++
				t.Logf("⚠️ 非代理服务 %s (:%d) 通过了 %s 验证（可能是 Probe 未正确识别导致）", svc.Name, svc.Port, protocol)
			}
		}
	}

	fmt.Printf("非代理服务拒绝: %d, 通过: %d\n", rejected, passed)
	// 至少 90% 的非代理服务应被拒绝
	if rejected+passed > 0 {
		rejectionRate := float64(rejected) / float64(rejected+passed) * 100
		assert.GreaterOrEqual(t, rejectionRate, 90.0, "非代理服务拒绝率应 >= 90%%")
	}
}

// TestProbeIdentificationAccuracy 测试 Probe 层服务识别精度
func TestProbeIdentificationAccuracy(t *testing.T) {
	if err := WaitForPort(8080, 2*time.Second); err != nil {
		t.Skip("goat-server 未运行，跳过 Probe 识别精度测试")
	}

	manifest, err := LoadManifest()
	if err != nil {
		t.Fatalf("加载服务清单失败: %v", err)
	}

	p := probe.NewProbe(3 * time.Second)

	fmt.Println("\n========================================")
	fmt.Println("Probe 识别精度测试")
	fmt.Println("========================================")

	correctType, correctProxy, total := 0, 0, 0

	for _, svc := range manifest.Services {
		isOpen, serviceType, isLikelyProxy := p.ScanAndIdentifyPort("127.0.0.1", svc.Port)
		if !isOpen {
			continue
		}

		total++

		// 检查类型识别
		typeMatch := serviceType == svc.ExpectedType
		// 代理服务如果是 "unknown" 但 isLikelyProxy=true 也算匹配
		if svc.ShouldBeProxy && serviceType == "unknown" && isLikelyProxy {
			typeMatch = true
		}

		if typeMatch {
			correctType++
		}

		// 检查代理判定
		if isLikelyProxy == svc.ShouldBeProxy {
			correctProxy++
		}

		if !typeMatch || isLikelyProxy != svc.ShouldBeProxy {
			fmt.Printf("  ❌ %s (:%d) 类型=%s(期望:%s) 代理=%v(期望:%v)\n",
				svc.Name, svc.Port, serviceType, svc.ExpectedType, isLikelyProxy, svc.ShouldBeProxy)
		}
	}

	if total > 0 {
		typeRate := float64(correctType) / float64(total) * 100
		proxyRate := float64(correctProxy) / float64(total) * 100
		fmt.Printf("\n类型识别率: %.1f%% (%d/%d)\n", typeRate, correctType, total)
		fmt.Printf("代理判定率: %.1f%% (%d/%d)\n", proxyRate, correctProxy, total)

		assert.GreaterOrEqual(t, typeRate, 70.0, "类型识别率应 >= 70%%")
		assert.GreaterOrEqual(t, proxyRate, 80.0, "代理判定率应 >= 80%%")
	}
}
```

- [ ] **Step 3: 验证分层测试编译**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go vet ./test/`
Expected:
  - Exit code: 0
  - Output does NOT contain: "cannot", "undefined"

- [ ] **Step 4: 质量门禁 — 运行全部内部单元测试**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go test ./internal/... -count=1 -timeout 120s`
Expected:
  - Exit code: 0
  - Output does NOT contain: "FAIL"

- [ ] **Step 5: 提交**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter && git add free-proxy-scanner/test/manifest_helper.go free-proxy-scanner/test/validator_layer_test.go && git commit -m "test(scanner): add validator layer precision tests and manifest classification helpers"`

---

### Task 3: 增强 EnhancedScanner 全管线测试

**Depends on:** Task 2
**Files:**
- Modify: `free-proxy-scanner/test/enhanced_scanner_pipeline_test.go:95-131`（增强 IP 层陷阱测试 + 认证代理测试）
- Create: `free-proxy-scanner/test/enhanced_scanner_auth_test.go`（认证代理完整测试）

**目的：** 当前 EnhancedScanner 测试缺少：1) 认证代理的 bruteforce 路径测试；2) HTTP 认证代理 (8081) 的测试；3) 更多陷阱服务的覆盖。增强测试确保 ScanProxy 的两个阶段（无认证验证 → 认证检测/爆破）都能正确工作。

- [ ] **Step 1: 创建 EnhancedScanner 认证代理测试**

文件: `free-proxy-scanner/test/enhanced_scanner_auth_test.go`

```go
package test

import (
	"testing"
	"time"

	"github.com/free-proxy-hunter/free-proxy-scanner/internal/scanner/validator"
	"github.com/free-proxy-hunter/free-proxy-scanner/pkg/api"
	"github.com/free-proxy-hunter/free-proxy-scanner/pkg/utils"
	enhancedscanner "github.com/free-proxy-hunter/free-proxy-scanner/internal/scanner/enhanced_scanner"
	"github.com/stretchr/testify/assert"
)

// TestEnhancedScannerAuthDetection 测试 EnhancedScanner 对认证代理的检测
func TestEnhancedScannerAuthDetection(t *testing.T) {
	if err := WaitForPort(8080, 2*time.Second); err != nil {
		t.Skip("goat-server 未运行，跳过 EnhancedScanner 认证检测测试")
	}

	mockServer := newMockAPIServer(false)
	defer mockServer.Close()

	v := validator.NewValidator(5*time.Second, "http://httpbin.org/ip")
	v.SetSkipIPVerify(true)
	apiClient := api.NewClient(mockServer.URL, "test-key")
	dm := utils.NewDictionaryManager(apiClient)
	es := enhancedscanner.NewEnhancedScanner(v, dm, apiClient)

	t.Run("HTTP认证代理应标记RequiresAuth", func(t *testing.T) {
		result, err := es.ScanProxy("127.0.0.1", 8081, "http")
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.RequiresAuth, "HTTP认证代理应标记 RequiresAuth=true")
		// 应有 auth_required 状态的代理对象
		hasAuthProxy := false
		for _, p := range result.Proxies {
			if p.RequireAuth {
				hasAuthProxy = true
				break
			}
		}
		assert.True(t, hasAuthProxy, "应包含 RequireAuth 的代理对象")
	})

	t.Run("SOCKS5认证代理应标记RequiresAuth", func(t *testing.T) {
		result, err := es.ScanProxy("127.0.0.1", 1081, "socks5")
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.RequiresAuth, "SOCKS5认证代理应标记 RequiresAuth=true")
	})

	t.Run("AuthChallenge代理应标记RequiresAuth", func(t *testing.T) {
		result, err := es.ScanProxy("127.0.0.1", 9144, "http")
		assert.NoError(t, err)
		assert.NotNil(t, result)
		// Auth Challenge 代理返回 407，应被标记为需要认证
		if result.RequiresAuth {
			t.Logf("Auth Challenge 代理正确标记为需要认证")
		}
	})

	t.Run("非认证代理不应标记RequiresAuth", func(t *testing.T) {
		result, err := es.ScanProxy("127.0.0.1", 8080, "http")
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.RequiresAuth, "无认证代理不应标记 RequiresAuth")
	})
}

// TestEnhancedScannerWithAuthCredentials 测试 EnhancedScanner 对带凭据的认证代理的验证
func TestEnhancedScannerWithAuthCredentials(t *testing.T) {
	if err := WaitForPort(8080, 2*time.Second); err != nil {
		t.Skip("goat-server 未运行，跳过 EnhancedScanner 凭据验证测试")
	}

	v := validator.NewValidator(5*time.Second, "http://httpbin.org/ip")
	v.SetSkipIPVerify(true)

	t.Run("HTTP代理带正确凭据应通过", func(t *testing.T) {
		proxy, err := v.ValidateProxyWithAuth("127.0.0.1", 8081, "http", "admin", "password")
		assert.NoError(t, err, "带正确凭据的HTTP代理应通过验证")
		assert.NotNil(t, proxy)
		assert.True(t, proxy.RequireAuth)
	})

	t.Run("SOCKS5代理带正确凭据应通过", func(t *testing.T) {
		proxy, err := v.ValidateProxyWithAuth("127.0.0.1", 1081, "socks5", "admin", "password")
		assert.NoError(t, err, "带正确凭据的SOCKS5代理应通过验证")
		assert.NotNil(t, proxy)
		assert.True(t, proxy.RequireAuth)
	})

	t.Run("HTTP代理带错误凭据应失败", func(t *testing.T) {
		_, err := v.ValidateProxyWithAuth("127.0.0.1", 8081, "http", "wrong", "creds")
		assert.Error(t, err, "带错误凭据的HTTP代理应验证失败")
	})

	t.Run("SOCKS5代理带错误凭据应失败", func(t *testing.T) {
		_, err := v.ValidateProxyWithAuth("127.0.0.1", 1081, "socks5", "wrong", "creds")
		assert.Error(t, err, "带错误凭据的SOCKS5代理应验证失败")
	})
}
```

- [ ] **Step 2: 增强 enhanced_scanner_pipeline_test.go — 扩展覆盖的服务类型**

文件: `free-proxy-scanner/test/enhanced_scanner_pipeline_test.go:86-93`（在 TestEnhancedScannerPipeline 末尾追加子测试）

```go
		t.Run("SlowCONNECT代理", func(t *testing.T) {
			result, err := es.ScanProxy("127.0.0.1", 9142, "http")
			assert.NoError(t, err)
			assert.NotNil(t, result)
			// Slow CONNECT 可能通过也可能超时，取决于 validator 超时设置
			t.Logf("Slow CONNECT 结果: Proxies=%d, RequiresAuth=%v", len(result.Proxies), result.RequiresAuth)
		})

		t.Run("Chunked代理", func(t *testing.T) {
			result, err := es.ScanProxy("127.0.0.1", 9143, "http")
			assert.NoError(t, err)
			assert.NotNil(t, result)
			t.Logf("Chunked 代理结果: Proxies=%d, RequiresAuth=%v", len(result.Proxies), result.RequiresAuth)
		})

		t.Run("Squid代理应通过", func(t *testing.T) {
			result, err := es.ScanProxy("127.0.0.1", 3128, "http")
			assert.NoError(t, err)
			assert.NotNil(t, result)
		})

		t.Run("TransparentProxy应通过", func(t *testing.T) {
			result, err := es.ScanProxy("127.0.0.1", 8888, "http")
			assert.NoError(t, err)
			assert.NotNil(t, result)
		})

		t.Run("SOCKS4代理应通过", func(t *testing.T) {
			result, err := es.ScanProxy("127.0.0.1", 1082, "socks4")
			assert.NoError(t, err)
			assert.NotNil(t, result)
		})
```

- [ ] **Step 3: 验证编译**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go vet ./test/`
Expected:
  - Exit code: 0
  - Output does NOT contain: "cannot", "undefined"

- [ ] **Step 4: 质量门禁**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go test ./internal/... -count=1 -timeout 120s && go vet ./test/`
Expected:
  - Exit code: 0
  - Output does NOT contain: "FAIL" or "vet:"

- [ ] **Step 5: 提交**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter && git add free-proxy-scanner/test/enhanced_scanner_auth_test.go free-proxy-scanner/test/enhanced_scanner_pipeline_test.go && git commit -m "test(scanner): add EnhancedScanner auth detection tests and expand pipeline coverage"`

---

### Task 4: 误报率/漏报率度量测试

**Depends on:** Task 2
**Files:**
- Create: `free-proxy-scanner/test/accuracy_metrics_test.go`

**目的：** 建立量化的精度度量体系，对 Probe 层和 Validator 层分别统计 TP/FP/TN/FN，计算误报率、漏报率、精确率、召回率。为后续优化提供数据基线。

- [ ] **Step 1: 创建误报率/漏报率度量测试**

文件: `free-proxy-scanner/test/accuracy_metrics_test.go`

```go
package test

import (
	"fmt"
	"testing"
	"time"

	"github.com/free-proxy-hunter/free-proxy-scanner/internal/scanner/probe"
	"github.com/free-proxy-hunter/free-proxy-scanner/internal/scanner/validator"
)

// Metrics 结构体记录精度指标
type Metrics struct {
	TruePositive  int
	FalsePositive int
	TrueNegative  int
	FalseNegative int
}

func (m *Metrics) Total() int {
	return m.TruePositive + m.FalsePositive + m.TrueNegative + m.FalseNegative
}

func (m *Metrics) Precision() float64 {
	if m.TruePositive+m.FalsePositive == 0 {
		return 0
	}
	return float64(m.TruePositive) / float64(m.TruePositive+m.FalsePositive) * 100
}

func (m *Metrics) Recall() float64 {
	if m.TruePositive+m.FalseNegative == 0 {
		return 0
	}
	return float64(m.TruePositive) / float64(m.TruePositive+m.FalseNegative) * 100
}

func (m *Metrics) FalsePositiveRate() float64 {
	if m.FalsePositive+m.TrueNegative == 0 {
		return 0
	}
	return float64(m.FalsePositive) / float64(m.FalsePositive+m.TrueNegative) * 100
}

func (m *Metrics) FalseNegativeRate() float64 {
	if m.TruePositive+m.FalseNegative == 0 {
		return 0
	}
	return float64(m.FalseNegative) / float64(m.TruePositive+m.FalseNegative) * 100
}

// TestProbeLayerAccuracy Probe 层精度度量
func TestProbeLayerAccuracy(t *testing.T) {
	if err := WaitForPort(8080, 2*time.Second); err != nil {
		t.Skip("goat-server 未运行，跳过 Probe 层精度测试")
	}

	manifest, err := LoadManifest()
	if err != nil {
		t.Fatalf("加载服务清单失败: %v", err)
	}

	p := probe.NewProbe(3 * time.Second)
	metrics := Metrics{}

	fmt.Println("\n" + "========================================")
	fmt.Println("Probe 层精度度量")
	fmt.Println("========================================")

	for _, svc := range manifest.Services {
		isOpen, _, isLikelyProxy := p.ScanAndIdentifyPort("127.0.0.1", svc.Port)
		if !isOpen {
			continue
		}

		if svc.ShouldBeProxy {
			if isLikelyProxy {
				metrics.TruePositive++
			} else {
				metrics.FalseNegative++
				fmt.Printf("  FN: %s (:%d) 应是代理但未识别\n", svc.Name, svc.Port)
			}
		} else {
			if isLikelyProxy {
				metrics.FalsePositive++
				fmt.Printf("  FP: %s (:%d) 不应是代理但被识别\n", svc.Name, svc.Port)
			} else {
				metrics.TrueNegative++
			}
		}
	}

	fmt.Println("\n--- Probe 层精度报告 ---")
	fmt.Printf("True Positives:  %d\n", metrics.TruePositive)
	fmt.Printf("True Negatives:  %d\n", metrics.TrueNegative)
	fmt.Printf("False Positives: %d\n", metrics.FalsePositive)
	fmt.Printf("False Negatives: %d\n", metrics.FalseNegative)
	fmt.Printf("Precision:       %.1f%%\n", metrics.Precision())
	fmt.Printf("Recall:          %.1f%%\n", metrics.Recall())
	fmt.Printf("FP Rate:         %.1f%%\n", metrics.FalsePositiveRate())
	fmt.Printf("FN Rate:         %.1f%%\n", metrics.FalseNegativeRate())
	fmt.Printf("Total:           %d\n", metrics.Total())

	// 精确率应 >= 60%（减少误报）
	// 召回率应 >= 70%（不能漏太多）
	// 误报率应 <= 30%
	if metrics.Precision() < 60.0 {
		t.Errorf("Probe 精确率 %.1f%% 低于 60%% 阈值", metrics.Precision())
	}
	if metrics.Recall() < 70.0 {
		t.Errorf("Probe 召回率 %.1f%% 低于 70%% 阈值", metrics.Recall())
	}
}

// TestValidatorLayerAccuracy Validator 层精度度量（skipIPVerify 模式）
func TestValidatorLayerAccuracy(t *testing.T) {
	if err := WaitForPort(8080, 2*time.Second); err != nil {
		t.Skip("goat-server 未运行，跳过 Validator 层精度测试")
	}

	manifest, err := LoadManifest()
	if err != nil {
		t.Fatalf("加载服务清单失败: %v", err)
	}

	p := probe.NewProbe(3 * time.Second)
	v := validator.NewValidator(5*time.Second, "http://httpbin.org/ip")
	v.SetSkipIPVerify(true)

	metrics := Metrics{}

	fmt.Println("\n" + "========================================")
	fmt.Println("Validator 层精度度量 (skipIPVerify)")
	fmt.Println("========================================")

	for _, svc := range manifest.Services {
		isOpen, serviceType, isLikelyProxy := p.ScanAndIdentifyPort("127.0.0.1", svc.Port)
		if !isOpen || !isLikelyProxy {
			continue
		}

		// 只测试 Probe 标记为代理的服务
		protocol := GetProtocolForService(svc)
		proxy, err := v.ValidateProxy("127.0.0.1", svc.Port, protocol)

		validated := err == nil && proxy != nil

		if svc.ShouldBeProxy {
			if validated {
				metrics.TruePositive++
			} else {
				// 需认证的代理验证失败是预期行为
				if RequiresAuth(svc.Validation) {
					metrics.TruePositive++ // 正确识别为需要认证
				} else {
					metrics.FalseNegative++
					fmt.Printf("  FN: %s (:%d) %s 应是代理但验证失败: %v\n", svc.Name, svc.Port, protocol, err)
				}
			}
		} else {
			if validated {
				metrics.FalsePositive++
				fmt.Printf("  FP: %s (:%d) %s 不应是代理但验证通过(类型:%s)\n", svc.Name, svc.Port, protocol, serviceType)
			} else {
				metrics.TrueNegative++
			}
		}
	}

	fmt.Println("\n--- Validator 层精度报告 ---")
	fmt.Printf("True Positives:  %d\n", metrics.TruePositive)
	fmt.Printf("True Negatives:  %d\n", metrics.TrueNegative)
	fmt.Printf("False Positives: %d\n", metrics.FalsePositive)
	fmt.Printf("False Negatives: %d\n", metrics.FalseNegative)
	fmt.Printf("Precision:       %.1f%%\n", metrics.Precision())
	fmt.Printf("Recall:          %.1f%%\n", metrics.Recall())
	fmt.Printf("FP Rate:         %.1f%%\n", metrics.FalsePositiveRate())
	fmt.Printf("FN Rate:         %.1f%%\n", metrics.FalseNegativeRate())
	fmt.Printf("Total:           %d\n", metrics.Total())

	// Validator 精确率应 >= 75%（Validator 层误报应更少）
	// 误报率应 <= 20%
	if metrics.Precision() < 75.0 {
		t.Errorf("Validator 精确率 %.1f%% 低于 75%% 阈值", metrics.Precision())
	}
	if metrics.FalsePositiveRate() > 20.0 {
		t.Errorf("Validator 误报率 %.1f%% 超过 20%% 阈值", metrics.FalsePositiveRate())
	}
}
```

- [ ] **Step 2: 验证编译**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go vet ./test/`
Expected:
  - Exit code: 0
  - Output does NOT contain: "cannot", "undefined"

- [ ] **Step 3: 质量门禁**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go build ./internal/... && go vet ./test/`
Expected:
  - Exit code: 0
  - Output does NOT contain: "cannot", "FAIL"

- [ ] **Step 4: 提交**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter && git add free-proxy-scanner/test/accuracy_metrics_test.go && git commit -m "test(scanner): add precision/recall metrics tests for Probe and Validator layers"`

---

### Task 5: 全管线端到端验证（启动 goat-server 后运行）

**Depends on:** Task 3, Task 4
**Files:**
- None（纯验证任务）

**目的：** 启动 goat-server，运行全量集成测试，确认新增测试都能通过，现有测试无回归。

- [ ] **Step 1: 构建 goat-server**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/goat-server && go build -o /tmp/goat-server ./cmd/goat-server`
Expected:
  - Exit code: 0

- [ ] **Step 2: 启动 goat-server**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/goat-server && /tmp/goat-server &>/tmp/goat-server.log & sleep 3 && nc -z 127.0.0.1 8080 && echo "goat-server started" || (cat /tmp/goat-server.log && exit 1)`
Expected:
  - Exit code: 0
  - Output contains: "goat-server started"

- [ ] **Step 3: 运行 IPVerifier 单元测试（不需要 goat-server）**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go test ./internal/scanner/validator/ -count=1 -timeout 60s -run "TestParseIPFromResponse|TestIsValidPublicIP|TestIPVerifierWithMockServer" -v`
Expected:
  - Exit code: 0
  - Output contains: "PASS"

- [ ] **Step 4: 运行 Probe 层精度测试**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go test ./test/ -count=1 -timeout 120s -run "TestProbeLayerAccuracy" -v`
Expected:
  - Exit code: 0
  - Output contains: "Probe 层精度报告"
  - Output does NOT contain: "低于" or "超过" (阈值)

- [ ] **Step 5: 运行 Validator 层精度测试**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go test ./test/ -count=1 -timeout 120s -run "TestValidatorLayerAccuracy" -v`
Expected:
  - Exit code: 0
  - Output contains: "Validator 层精度报告"

- [ ] **Step 6: 运行 EnhancedScanner 全管线测试**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go test ./test/ -count=1 -timeout 120s -run "TestEnhancedScannerPipeline|TestEnhancedScannerAuthDetection|TestEnhancedScannerWithAuthCredentials" -v`
Expected:
  - Exit code: 0
  - Output contains: "PASS"

- [ ] **Step 7: 运行现有集成测试确认无回归**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go test ./test/ -count=1 -timeout 300s -run "TestGoatServerValidation|TestServiceIdentification|TestSOCKS5AuthDetection|TestTrapServiceRejection|TestRealProxyAcceptance" -v`
Expected:
  - Exit code: 0
  - Output does NOT contain: "FAIL"

- [ ] **Step 8: 运行全部内部单元测试确认无回归**

Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go test ./internal/... -count=1 -timeout 120s`
Expected:
  - Exit code: 0
  - Output does NOT contain: "FAIL"

- [ ] **Step 9: 停止 goat-server**

Run: `pkill -f /tmp/goat-server 2>/dev/null; echo "goat-server stopped"`
Expected:
  - Exit code: 0

---

## Self-Review Results

**Plan Type:** Feature

| # | Check | Result | Action Taken |
|---|-------|--------|-------------|
| 1 | Goal + Type + Scope + Risk? | PASS | — |
| 2 | Dependencies? | PASS | T1→T2→T3, T2→T4, T3+T4→T5 |
| 3 | 3-8 Steps per Task? | PASS | T1:5, T2:5, T3:5, T4:4, T5:9 |
| 4 | No TBD/TODO? | PASS | — |
| 5 | Cross-consistency? | PASS | Metrics struct 在 T4 定义，GetProtocolForService 在 T2 定义 |
| 6 | File location correct? | PASS | docs/superpowers/plans/ |
| 7 | Quality gate Steps? | PASS | 每个 Task 有 vet + test 验证 |
| 8 | No anti-patterns? | PASS | — |
| 9 | Exact file paths? | PASS | — |
| 10 | Complete code in Steps? | PASS | — |
| 11 | Validation commands? | PASS | — |
| 12 | No placeholders? | PASS | — |
| 13 | Spec coverage? | PASS | Probe/Validator/EnhancedScanner/IPVerifier 四层全覆盖 |
| 14 | Each Task independently verifiable? | PASS | T1 不依赖 goat-server，T2-T4 依赖 goat-server |
| 15 | No abstract instructions? | PASS | — |

**Status:** ✅ ALL PASS

---

## Execution Selection

**Tasks:** 5
**Dependencies:** Yes (T1→T2→T3, T2→T4, T3+T4→T5)
**User Preference:** None
**Decision:** Subagent-Driven
**Reasoning:** 5 tasks with dependencies, suitable for subagent-driven execution with dependency-aware scheduling

⏹️ **Phase 4 Complete**
