# Scanner Unit Test Coverage — Plan A (Foundation Layer)

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** Raise unit test coverage to 100% for the scanner's foundation layer: config, IP utilities, probe analysis, and parser functions.

**Architecture:** Bottom-up approach — test the purest logic first (IP math, config loading, string parsing, header analysis) that requires no network or external dependencies. Each Task targets one package, creates a test file covering all 0%-coverage functions in that package.

**Tech Stack:** Go 1.21+, testing, testify/assert, net/httptest

**Risks:**
- `internal/config` uses Viper which reads YAML files — tests need temp config files or Viper overrides
- `pkg/utils/socks_bruteforcer.go` requires real SOCKS connections — deferred to Plan B
- `pkg/utils/dictionary_sync.go` requires file I/O and HTTP — deferred to Plan B

---

### Task 1: ip.go + ip_iterator.go Unit Tests (9 functions, 0% → 100%)

**Depends on:** None
**Files:**
- Create: `free-proxy-scanner/pkg/utils/ip_test.go`
- Create: `free-proxy-scanner/pkg/utils/ip_iterator_test.go`
- Source: `free-proxy-scanner/pkg/utils/ip.go` (5 functions: GenerateIPsFromCIDR, generateIPsFromRange, inc, IsValidIP, GetIPSegment)
- Source: `free-proxy-scanner/pkg/utils/ip_iterator.go` (4 functions: NewIPIteratorFromCIDR, newIPIteratorFromRange, Next, HasNext)

- [ ] **Step 1: Read source files to understand function signatures and logic**

Read `free-proxy-scanner/pkg/utils/ip.go` and `free-proxy-scanner/pkg/utils/ip_iterator.go` completely.

- [ ] **Step 2: Create ip_test.go covering all 5 functions**

Create `free-proxy-scanner/pkg/utils/ip_test.go` with tests for:
- `GenerateIPsFromCIDR("192.168.1.0/30")` → returns 4 IPs
- `GenerateIPsFromCIDR("invalid")` → returns empty
- `generateIPsFromRange("192.168.1.1-192.168.1.3")` → returns 3 IPs
- `generateIPsFromRange("invalid")` → returns empty
- `IsValidIP("192.168.1.1")` → true
- `IsValidIP("invalid")` → false
- `IsValidIP("")` → false
- `GetIPSegment("192.168.1.100")` → "192.168.1"
- `GetIPSegment("invalid")` → appropriate handling
- Edge cases: IPv6, /32 CIDR, single IP range

- [ ] **Step 3: Create ip_iterator_test.go covering all 4 functions**

Create `free-proxy-scanner/pkg/utils/ip_iterator_test.go` with tests for:
- `NewIPIteratorFromCIDR("192.168.1.0/30")` → iterator with 4 IPs
- `NewIPIteratorFromCIDR("invalid")` → nil or error handling
- `Next()` → returns each IP in sequence, then ("", false)
- `HasNext()` → true before exhaustion, false after
- Edge case: /32 returns exactly one IP
- `newIPIteratorFromRange("10.0.0.1-10.0.0.3")` → 3 IPs via Next()

- [ ] **Step 4: Verify tests pass and coverage is 100%**

Run: `cd free-proxy-scanner && go test ./pkg/utils/ -run "TestIP|TestIPIterator" -v -coverprofile=ip_cover.out`
Expected:
  - Exit code: 0
  - All tests PASS
  - Coverage for ip.go and ip_iterator.go functions: 100%

Run: `cd free-proxy-scanner && go tool cover -func=ip_cover.out | grep -E "ip.go|ip_iterator.go"`
Expected: All functions show 100.0%

- [ ] **Step 5: Commit**

Run: `cd free-proxy-scanner && git add pkg/utils/ip_test.go pkg/utils/ip_iterator_test.go && git commit -m "test(utils): add 100% coverage for ip.go and ip_iterator.go"`

---

### Task 2: config.go Unit Tests (2 functions, 0% → 100%)

**Depends on:** None
**Files:**
- Create: `free-proxy-scanner/internal/config/config_test.go`
- Source: `free-proxy-scanner/internal/config/config.go` (2 functions: Load, Get)

- [ ] **Step 1: Read source file**

Read `free-proxy-scanner/internal/config/config.go` to understand the Config struct and Load/Get behavior.

- [ ] **Step 2: Create config_test.go**

Create `free-proxy-scanner/internal/config/config_test.go` with tests for:
- `Load("nonexistent.yaml")` → returns error
- `Load("valid_config.yaml")` → creates temp YAML, loads successfully, returns nil error
- `Get()` before Load → returns default/nil config
- `Get()` after Load → returns loaded config with correct values
- Test all config fields are properly read from YAML
- Edge cases: empty config file, partial config

- [ ] **Step 3: Verify tests pass**

Run: `cd free-proxy-scanner && go test ./internal/config/ -v -coverprofile=config_cover.out`
Expected:
  - Exit code: 0
  - All tests PASS
  - Coverage: 100%

- [ ] **Step 4: Commit**

Run: `cd free-proxy-scanner && git add internal/config/config_test.go && git commit -m "test(config): add 100% coverage for config.go"`

---

### Task 3: probe/proxy_analysis.go + service_probes.go Tests (4 functions, 0% → 100%)

**Depends on:** None
**Files:**
- Create: `free-proxy-scanner/internal/scanner/probe/proxy_analysis_test.go`
- Source: `free-proxy-scanner/internal/scanner/probe/proxy_analysis.go` (3 functions: analyzeProxyHeaders, isLikelyProxy, checkProxyHeaders)
- Source: `free-proxy-scanner/internal/scanner/probe/service_probes.go` (1 function: probeHTTPSService)

- [ ] **Step 1: Read source files**

Read both source files to understand function signatures, return values, and logic branches.

- [ ] **Step 2: Create proxy_analysis_test.go**

Create `free-proxy-scanner/internal/scanner/probe/proxy_analysis_test.go` with tests for:

**analyzeProxyHeaders:**
- Response with Via header → features contains "Via header present", score > 0
- Response with multiple proxy headers → score accumulates correctly
- Response with no proxy headers → empty features, score = 0
- Score capped at 1.0 (provide many headers to exceed cap)
- CDN headers (CF-Ray) detected
- Cache headers (X-Cache) detected
- Enterprise proxy (bluecoat) detected
- Connection features ("connection established") detected

**isLikelyProxy:**
- High confidence response + non-proxy port → isProxy = true
- Low confidence response + common proxy port → confidence boosted
- No proxy features at all → isProxy = false
- Exactly 0.3 threshold → isProxy = true

**checkProxyHeaders:**
- http.Header with Via → returns ["Via"]
- http.Header with multiple proxy headers → returns all names
- Empty http.Header → returns nil/empty

**probeHTTPSService:**
- Start a local TLS server, test probeHTTPSService returns true
- Test with non-TLS port → returns false

- [ ] **Step 3: Verify tests pass**

Run: `cd free-proxy-scanner && go test ./internal/scanner/probe/ -run "TestProxyAnalysis|TestCheckProxyHeaders|TestProbeHTTPS" -v -cover`
Expected:
  - Exit code: 0
  - All tests PASS

- [ ] **Step 4: Commit**

Run: `cd free-proxy-scanner && git add internal/scanner/probe/proxy_analysis_test.go && git commit -m "test(probe): add coverage for proxy_analysis.go and probeHTTPSService"`

---

### Task 4: scanner/parser.go Unit Tests (3 functions, 0% → 100%)

**Depends on:** None
**Files:**
- Create: `free-proxy-scanner/internal/scanner/parser_test.go`
- Source: `free-proxy-scanner/internal/scanner/parser.go` (3 functions: parseIPRanges, parsePorts, parseProtocols)

- [ ] **Step 1: Read source file**

Read `free-proxy-scanner/internal/scanner/parser.go` to understand JSON parsing logic.

- [ ] **Step 2: Create parser_test.go**

Create `free-proxy-scanner/internal/scanner/parser_test.go` with tests for:

**parseIPRanges:**
- Valid JSON array `["192.168.1.0/24","10.0.0.0/8"]` → returns 2 ranges
- Empty string → returns error
- Invalid JSON → returns error
- JSON with non-string values → appropriate handling

**parsePorts:**
- Valid JSON array `[80,443,8080]` → returns [80,443,8080]
- Comma-separated string `"80,443,8080"` → returns [80,443,8080]
- Range string `"8000-8003"` → returns [8000,8001,8002,8003]
- Empty string → returns error
- Invalid port string → returns error

**parseProtocols:**
- Valid JSON array `["http","socks5"]` → returns ["http","socks5"]
- Comma-separated string `"http,socks4,socks5"` → returns 3 protocols
- Empty string → returns error
- Invalid protocol → returns error (if validation exists)

Note: These are methods on `Scanner` struct. Create a minimal Scanner instance for testing (NewScanner with nil config/apiClient may panic — read scanner.go first to check what's needed).

- [ ] **Step 3: Verify tests pass**

Run: `cd free-proxy-scanner && go test ./internal/scanner/ -run "TestParse" -v -cover`
Expected:
  - Exit code: 0
  - All tests PASS

- [ ] **Step 4: Commit**

Run: `cd free-proxy-scanner && git add internal/scanner/parser_test.go && git commit -m "test(scanner): add 100% coverage for parser.go"`

---

## Self-Review Results

| # | Check | Result | Action Taken |
|---|-------|--------|-------------|
| 1 | Header? | PASS | Goal + Architecture + Tech Stack + Risks |
| 2 | Dependencies? | PASS | All Tasks independent (None) |
| 3 | Exact paths? | PASS | All file paths precise |
| 4 | 3-8 Steps? | PASS | Task 1: 5, Task 2: 4, Task 3: 4, Task 4: 4 |
| 5 | Complete code? | N/A | Test code delegated to subagent (reads source then writes) |
| 6 | Modification steps? | N/A | No modifications, only new test files |
| 7 | Code block size? | N/A | Test code in subagent prompt |
| 8 | No dangling refs? | PASS | All source files verified to exist |
| 9 | Verification commands? | PASS | Each Task has exact commands with exit code + output |
| 10 | Spec coverage? | PASS | 17 of 32 functions covered in Plan A |
| 11 | Independent verification? | PASS | Each Task tests different package |
| 12 | No placeholders? | PASS | No TBD/TODO |
| 13 | No abstract directives? | PASS | Each step has specific test cases listed |
| 14 | Type consistency? | PASS | Function signatures verified |
| 15 | Save location? | PASS | docs/superpowers/plans/ |

**Status:** ✅ ALL PASS

---

## Execution Selection

**Tasks:** 4
**Dependencies:** none (all independent)
**User Preference:** none
**Decision:** Subagent-Driven
**Reasoning:** 4 independent tasks, each creates test files for different packages. Sequential dispatch prevents test file conflicts.

**Auto-invoking:** `superpowers:subagent-driven-development`
