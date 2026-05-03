# Scanner Bug Fix & Code Quality Improvement Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** Fix all compilation errors, test failures, and code quality issues in the free-proxy-scanner module.

**Architecture:** The scanner module has three categories of issues: (1) unused imports preventing compilation, (2) a logic bug in banner analysis causing false proxy detection for normal web servers, and (3) IPv6-incompatible address formatting flagged by `go vet`. Each is isolated to specific files and can be fixed independently.

**Tech Stack:** Go, net package, testing

---

### Task 1: Fix Compilation Errors — Unused Imports in pkg/api

**Files:**
- Modify: `free-proxy-scanner/pkg/api/dictionary_client.go:8`
- Modify: `free-proxy-scanner/pkg/api/scanner_client.go:7`

- [ ] **Step 1: Remove unused import from dictionary_client.go**

Remove the `"github.com/go-resty/resty/v2"` import line from the import block. The file uses `c.client.R()` which is already available through the Client struct defined elsewhere in the package.

```go
// Before (lines 3-9):
import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-resty/resty/v2"
)

// After:
import (
	"encoding/json"
	"fmt"
	"time"
)
```

- [ ] **Step 2: Remove unused import from scanner_client.go**

```go
// Before (lines 3-8):
import (
	"encoding/json"
	"fmt"

	"github.com/go-resty/resty/v2"
)

// After:
import (
	"encoding/json"
	"fmt"
)
```

- [ ] **Step 3: Verify compilation**

Run: `cd free-proxy-scanner && go build ./...`
Expected: No output (clean build, exit code 0)

---

### Task 2: Fix False Proxy Detection Bug in analyzeBanner

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/probe/probe.go:163-171`
- Test: `free-proxy-scanner/internal/scanner/probe/proxy_features_test.go:119-139`

- [ ] **Step 1: Understand the bug**

The test `TestAnalyzeProxyFeatures/分析普通Web服务器响应` creates an httptest server that sets `Server: nginx/1.18.0` and `Content-Type: text/html` headers. When `conn.Read` reads the raw HTTP response, `analyzeBanner` detects `HTTP/` prefix and enters the HTTP branch.

The current logic at lines 164-169 requires ALL of: `server:` header present, NOT `squid`, `content-type:` present, AND `content-length:` present — to classify as non-proxy. But `httptest` servers may not include `Content-Length:` for simple responses, causing the code to fall through to line 171 `return "http-proxy", true` — a false positive.

The fix: a web server with a `Server:` header (not matching known proxy servers like squid, tinyproxy, varnish, etc.) and a `Content-Type:` header should be classified as a normal HTTP server, not requiring `Content-Length:`.

- [ ] **Step 2: Fix the analyzeBanner HTTP detection logic**

Replace lines 163-171 in `probe.go`:

```go
// Before:
// 检查是否为普通Web服务器（包含Server头但不是代理）
if strings.Contains(bannerLower, "server:") && !strings.Contains(bannerLower, "squid") {
	// 如果有Content-Type和Content-Length，很可能是普通Web服务器
	if strings.Contains(bannerLower, "content-type:") && strings.Contains(bannerLower, "content-length:") {
		return "http", false
	}
}
// 其他HTTP响应，可能是代理
return "http-proxy", true

// After:
// 检查是否为普通Web服务器（包含Server头但不是已知代理软件）
knownProxyServers := []string{"squid", "tinyproxy", "varnish", "privoxy", "polipo", "ccproxy", "winproxy"}
if strings.Contains(bannerLower, "server:") {
	isKnownProxy := false
	for _, ps := range knownProxyServers {
		if strings.Contains(bannerLower, ps) {
			isKnownProxy = true
			break
		}
	}
	if !isKnownProxy {
		// 有Server头且不是已知代理软件，判定为普通Web服务器
		return "http", false
	}
}
// 其他HTTP响应，可能是代理
return "http-proxy", true
```

- [ ] **Step 3: Run the specific failing test**

Run: `cd free-proxy-scanner && go test ./internal/scanner/probe/ -run TestAnalyzeProxyFeatures -v`
Expected: All sub-tests PASS, exit code 0

- [ ] **Step 4: Run all probe tests to ensure no regression**

Run: `cd free-proxy-scanner && go test ./internal/scanner/probe/ -v`
Expected: All tests PASS, exit code 0

---

### Task 3: Fix IPv6 Address Format Warnings

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/enhanced/port_scanner.go:46,99`
- Modify: `free-proxy-scanner/internal/scanner/enhanced/service_identifier.go:30,212`
- Modify: `free-proxy-scanner/internal/scanner/probe/probe.go:24,40`
- Modify: `free-proxy-scanner/internal/scanner/probe/proxy_probes.go:64,156,225`
- Modify: `free-proxy-scanner/internal/scanner/probe/socks_probes.go:10,43`
- Modify: `free-proxy-scanner/internal/scanner/validator/socks_validator.go:20`

- [ ] **Step 1: Add net import where missing and replace fmt.Sprintf with net.JoinHostPort**

The pattern `fmt.Sprintf("%s:%d", ip, port)` does not work with IPv6 addresses (which require brackets like `[::1]:8080`). Replace all occurrences with `net.JoinHostPort(ip, strconv.Itoa(port))` or `net.JoinHostPort(ip, fmt.Sprintf("%d", port))`.

For each file, the change pattern is:

```go
// Before:
address := fmt.Sprintf("%s:%d", ip, port)
conn, err := net.DialTimeout("tcp", address, p.timeout)

// After:
address := net.JoinHostPort(ip, strconv.Itoa(port))
conn, err := net.DialTimeout("tcp", address, p.timeout)
```

Files and specific changes:

**probe.go** — Add `"strconv"` to imports, replace:
- Line 24: `address := net.JoinHostPort(ip, strconv.Itoa(port))`
- Line 40: `address := net.JoinHostPort(ip, strconv.Itoa(port))`

**proxy_probes.go** — Add `"strconv"` to imports, replace:
- Line 64: `address := net.JoinHostPort(ip, strconv.Itoa(port))`
- Line 156: `address := net.JoinHostPort(ip, strconv.Itoa(port))`
- Line 225: `address := net.JoinHostPort(ip, strconv.Itoa(port))`

**socks_probes.go** — Add `"strconv"` to imports, replace:
- Line 10: `address := net.JoinHostPort(ip, strconv.Itoa(port))`
- Line 43: `address := net.JoinHostPort(ip, strconv.Itoa(port))`

**port_scanner.go** — Add `"strconv"` to imports if missing, replace:
- Line 46: `addr := net.JoinHostPort(host, strconv.Itoa(port))`
- Line 99: `addr := net.JoinHostPort(host, strconv.Itoa(port))`

**service_identifier.go** — Add `"strconv"` to imports if missing, replace:
- Line 30: `address := net.JoinHostPort(host, strconv.Itoa(port))`
- Line 212: `address := net.JoinHostPort(host, strconv.Itoa(port))`

**socks_validator.go** — Add `"strconv"` to imports if missing, replace:
- Line 20: `address := net.JoinHostPort(ip, strconv.Itoa(port))`

- [ ] **Step 2: Verify go vet passes**

Run: `cd free-proxy-scanner && go vet ./internal/scanner/...`
Expected: No output (exit code 0)

- [ ] **Step 3: Verify full build passes**

Run: `cd free-proxy-scanner && go build ./...`
Expected: No output (exit code 0)

- [ ] **Step 4: Run all scanner tests**

Run: `cd free-proxy-scanner && go test ./internal/scanner/... -count=1`
Expected: All packages PASS (or skip), exit code 0

---
