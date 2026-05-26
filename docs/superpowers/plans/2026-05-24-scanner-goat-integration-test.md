# Scanner-Goat Integration Test Enhancement Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 利用 goat-server 靶场的全部 73 个服务，对 scanner 模块（Probe → Validator → EnhancedScanner）做端到端集成测试，覆盖 SOCKS5 认证检测、陷阱服务拒绝、EnhancedScanner 全管线、动态 trap 检测等当前零覆盖的关键路径。

**Architecture:** goat-server 启动 73 个服务 → 测试代码加载 manifest → 对每个服务按层测试：Probe 层（ScanAndIdentifyPort）→ Validator 层（ValidateProxy/ValidateProxyWithAuth）→ EnhancedScanner 层（ScanProxy 全管线）。陷阱服务验证 Validator 正确拒绝，代理服务验证正确通过，认证服务验证 auth 检测。

**Tech Stack:** Go 1.26, goat-server (test harness), testify/assert, service_manifest.yaml

**Scope:** Medium
**Risk:** Low（仅新增测试代码，不修改生产逻辑）

**Risks:**
- goat-server 未运行时测试应自动 skip，不阻塞 CI
- EnhancedScanner 需要 mock API server 返回 bruteforce 配置
- SOCKS5 认证服务 (9130/9131/9151) 的验证可能受网络环境影响

**Autonomy Level:** Full

---

### Task 1: SOCKS5 认证检测集成测试

**Depends on:** None
**Files:**
- Create: `test/socks5_auth_detection_test.go`

- [ ] **Step 1: 创建 SOCKS5 认证检测测试文件**

```go
package test

import (
	"testing"
	"time"

	"github.com/free-proxy-hunter/free-proxy-scanner/internal/scanner/probe"
	"github.com/stretchr/testify/assert"
)

// TestSOCKS5AuthDetection 测试 probeSOCKS5 对 goat-server SOCKS5 认证变体服务的检测
// 覆盖端口: 1080 (no-auth), 1081 (auth-required), 9130 (auth-reject), 9131 (no-auth-only), 9151 (userpass-only)
func TestSOCKS5AuthDetection(t *testing.T) {
	if err := WaitForPort(1080, 2*time.Second); err != nil {
		t.Skip("goat-server 未运行，跳过 SOCKS5 认证检测测试")
	}

	p := probe.NewProbe(3 * time.Second)

	tests := []struct {
		name       string
		port       int
		wantSOCKS5 bool
		wantAuth   bool
	}{
		{"SOCKS5无认证代理", 1080, true, false},
		{"SOCKS5需认证代理", 1081, true, true},
		{"SOCKS5认证拒绝", 9130, true, true},
		{"SOCKS5仅无认证", 9131, true, false},
		{"SOCKS5仅用户名密码", 9151, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isSOCKS5, needsAuth := p.ProbeSOCKS5Public("127.0.0.1", tt.port)
			assert.Equal(t, tt.wantSOCKS5, isSOCKS5, "SOCKS5 检测结果")
			assert.Equal(t, tt.wantAuth, needsAuth, "认证需求检测结果")
		})
	}
}
```

- [ ] **Step 2: 导出 probeSOCKS5 为公共方法**

需要将 `probe.probeSOCKS5` 导出为 `Probe.ProbeSOCKS5Public` 以便测试包调用。

文件: `internal/scanner/probe/socks_probes.go`

在 `probeSOCKS5` 函数后添加：

```go
// ProbeSOCKS5Public 导出的 SOCKS5 探测方法，供集成测试使用
func (p *Probe) ProbeSOCKS5Public(ip string, port int) (bool, bool) {
	return p.probeSOCKS5(ip, port)
}
```

- [ ] **Step 3: 验证 SOCKS5 认证检测测试**
Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go test ./test/ -count=1 -timeout 30s -run "TestSOCKS5AuthDetection" -v`
Expected:
  - Exit code: 0
  - Output contains: "PASS"

- [ ] **Step 4: 质量门禁**
Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go build ./internal/scanner/probe/... && go build ./test/`
Expected:
  - Exit code: 0

---

### Task 2: 陷阱服务 Validator 拒绝测试

**Depends on:** None
**Files:**
- Create: `test/trap_service_validation_test.go`

- [ ] **Step 1: 创建陷阱服务验证测试**

测试 Validator 对 Probe 误判为代理的陷阱服务（9140/9141/9163/9164/9169/9170）能正确拒绝。

```go
package test

import (
	"testing"
	"time"

	"github.com/free-proxy-hunter/free-proxy-scanner/internal/scanner/validator"
	"github.com/stretchr/testify/assert"
)

// TestTrapServiceRejection 测试 Validator 正确拒绝陷阱服务
func TestTrapServiceRejection(t *testing.T) {
	if err := WaitForPort(8080, 2*time.Second); err != nil {
		t.Skip("goat-server 未运行，跳过陷阱服务测试")
	}

	v := validator.NewValidator(5*time.Second, "http://httpbin.org/ip")
	v.SetSkipIPVerify(true)

	// 陷阱服务：Probe 误判为代理，但 Validator 应拒绝
	trapServices := []struct {
		name     string
		port     int
		protocol string
	}{
		{"AbsoluteURIGETOnlyProxy", 9140, "http"},
		{"CONNECTRejectProxy", 9141, "http"},
		{"Minimal200Trap", 9163, "http"},
		{"ConnectGarbageTrap", 9164, "http"},
		{"VarnishCacheSite", 9169, "http"},
		{"ExpressLikeServer", 9170, "http"},
	}

	for _, tt := range trapServices {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v.ValidateProxy("127.0.0.1", tt.port, tt.protocol)
			assert.Error(t, err, "陷阱服务应该被 Validator 拒绝")
		})
	}
}

// TestRealProxyAcceptance 测试 Validator 正确接受真正的代理服务
func TestRealProxyAcceptance(t *testing.T) {
	if err := WaitForPort(8080, 2*time.Second); err != nil {
		t.Skip("goat-server 未运行，跳过真实代理测试")
	}

	v := validator.NewValidator(5*time.Second, "http://httpbin.org/ip")
	v.SetSkipIPVerify(true)

	realProxies := []struct {
		name     string
		port     int
		protocol string
	}{
		{"HTTPProxy", 8080, "http"},
		{"SOCKS5Proxy", 1080, "socks5"},
		{"HTTPSProxyVariant", 9171, "http"},
	}

	for _, tt := range realProxies {
		t.Run(tt.name, func(t *testing.T) {
			proxy, err := v.ValidateProxy("127.0.0.1", tt.port, tt.protocol)
			assert.NoError(t, err, "真实代理应该通过验证")
			assert.NotNil(t, proxy)
		})
	}
}
```

- [ ] **Step 2: 验证陷阱服务测试**
Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go test ./test/ -count=1 -timeout 60s -run "TestTrapServiceRejection|TestRealProxyAcceptance" -v`
Expected:
  - Exit code: 0
  - Output contains: "PASS"

- [ ] **Step 3: 质量门禁**
Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go build ./test/`
Expected:
  - Exit code: 0

---

### Task 3: EnhancedScanner 全管线集成测试

**Depends on:** Task 2
**Files:**
- Create: `test/enhanced_scanner_pipeline_test.go`

- [ ] **Step 1: 创建 EnhancedScanner 管线测试**

测试 EnhancedScanner.ScanProxy 对各类 goat-server 服务的完整处理流程。

```go
package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/free-proxy-hunter/free-proxy-scanner/internal/scanner/enhanced_scanner"
	"github.com/free-proxy-hunter/free-proxy-scanner/internal/scanner/validator"
	"github.com/free-proxy-hunter/free-proxy-scanner/pkg/api"
	"github.com/free-proxy-hunter/free-proxy-scanner/pkg/utils"
	"github.com/stretchr/testify/assert"
)

// newMockAPIServer 创建返回指定 bruteforce 配置的 mock API server
func newMockAPIServer(bruteforceEnabled bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config := map[string]interface{}{
			"system.enable_auth_bruteforce": bruteforceEnabled,
		}
		data, _ := json.Marshal(config)
		resp := api.Response{
			Code:      0,
			Message:   "success",
			Data:      data,
			Timestamp: time.Now().Unix(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
}

// TestEnhancedScannerPipeline 测试 EnhancedScanner 对 goat-server 服务的完整管线
func TestEnhancedScannerPipeline(t *testing.T) {
	if err := WaitForPort(8080, 2*time.Second); err != nil {
		t.Skip("goat-server 未运行，跳过 EnhancedScanner 管线测试")
	}

	mockServer := newMockAPIServer(false)
	defer mockServer.Close()

	v := validator.NewValidator(5*time.Second, "http://httpbin.org/ip")
	v.SetSkipIPVerify(true)
	apiClient := api.NewClient(mockServer.URL, "test-key")
	dm := utils.NewDictionaryManager(apiClient)
	es := enhanced_scanner.NewEnhancedScanner(v, dm, apiClient)

	t.Run("真实HTTP代理应通过", func(t *testing.T) {
		result, err := es.ScanProxy("127.0.0.1", 8080, "http")
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.Proxies)
		assert.False(t, result.RequiresAuth)
	})

	t.Run("真实SOCKS5代理应通过", func(t *testing.T) {
		result, err := es.ScanProxy("127.0.0.1", 1080, "socks5")
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.Proxies)
		assert.False(t, result.RequiresAuth)
	})

	t.Run("需认证HTTP代理应标记auth", func(t *testing.T) {
		result, err := es.ScanProxy("127.0.0.1", 8081, "http")
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.RequiresAuth)
	})

	t.Run("需认证SOCKS5代理应标记auth", func(t *testing.T) {
		result, err := es.ScanProxy("127.0.0.1", 1081, "socks5")
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.RequiresAuth)
	})

	t.Run("陷阱服务Minimal200应被拒绝", func(t *testing.T) {
		result, err := es.ScanProxy("127.0.0.1", 9163, "http")
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Empty(t, result.Proxies, "陷阱服务不应返回代理")
		assert.False(t, result.RequiresAuth)
	})

	t.Run("陷阱服务ConnectGarbage应被拒绝", func(t *testing.T) {
		result, err := es.ScanProxy("127.0.0.1", 9164, "http")
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Empty(t, result.Proxies)
		assert.False(t, result.RequiresAuth)
	})

	t.Run("非代理SSH应被拒绝", func(t *testing.T) {
		result, err := es.ScanProxy("127.0.0.1", 2222, "http")
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Empty(t, result.Proxies)
	})
}
```

- [ ] **Step 2: 验证 EnhancedScanner 管线测试**
Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go test ./test/ -count=1 -timeout 60s -run "TestEnhancedScannerPipeline" -v`
Expected:
  - Exit code: 0
  - Output contains: "PASS"

- [ ] **Step 3: 质量门禁**
Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go build ./test/`
Expected:
  - Exit code: 0

---

### Task 4: 动态 trap 检测与 goat_validation_test 重构

**Depends on:** Task 2
**Files:**
- Modify: `test/goat_validation_test.go:87-99`（替换硬编码端口为动态检测）
- Modify: `test/goat_validation_test.go:20-23`（添加 manifest 驱动的验证逻辑）

- [ ] **Step 1: 重构 goat_validation_test 中的硬编码端口**

将 `goat_validation_test.go` 中的硬编码 auth 端口和 trap 端口替换为从 manifest 读取。

文件: `test/goat_validation_test.go`

替换硬编码 auth 端口检查 `tc.Port == 8081 || tc.Port == 1081 || tc.Port == 9144` 为 `RequiresAuth(tc.Validation)`。

替换硬编码 trap 端口 map `map[int]bool{9140: true, 9141: true, 9163: true, 9164: true, 9169: true, 9170: true}` 为基于 manifest `category` 和 `validation` 字段的动态判断：如果 `should_be_proxy: true` 且 `validation: "full"` 且 Validator 拒绝了，则认为是陷阱服务（Probe 误判但 Validator 正确拒绝）。

- [ ] **Step 2: 验证重构后的测试**
Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go test ./test/ -count=1 -timeout 600s -run "TestGoatServerValidation" -v`
Expected:
  - Exit code: 0
  - Output contains: "测试总结: 成功 73, 失败 0"

- [ ] **Step 3: 质量门禁**
Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go build ./test/`
Expected:
  - Exit code: 0

---

### Task 5: 激活跳过的 proxy_validator_test

**Depends on:** None
**Files:**
- Modify: `test/proxy_validator_test.go:50-73`（替换 skip 为 goat-server 集成测试）

- [ ] **Step 1: 重写 proxy_validator_test 使用 goat-server**

将 `TestValidateRealProxy` 和 `TestValidateFakeProxyPort` 从 skip 改为使用 goat-server 服务。

文件: `test/proxy_validator_test.go`

替换 `TestValidateRealProxy`：使用 goat-server HTTP Proxy (8080) 替代手动代理。

替换 `TestValidateFakeProxyPort`：使用 goat-server SSH (2222) 或 Fake HTTP (9090) 替代。

- [ ] **Step 2: 验证重写的测试**
Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go test ./test/ -count=1 -timeout 30s -run "TestValidateRealProxy|TestValidateFakeProxyPort" -v`
Expected:
  - Exit code: 0
  - Output contains: "PASS"

- [ ] **Step 3: 质量门禁**
Run: `cd /Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner && go build ./test/`
Expected:
  - Exit code: 0
