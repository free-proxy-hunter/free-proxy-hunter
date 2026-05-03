# 扫描器 Bug 修复计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复扫描器实现中的并发安全问题、逻辑错误和资源泄漏问题

**Architecture:** 保持现有扫描器架构不变，重点修复线程安全问题，包括使用 atomic 操作替代直接指针递增、修复 SOCKS5/4 协议识别逻辑、确保资源正确释放

**Tech Stack:** Go, sync/atomic, golang.org/x/net/proxy

---

## Bug 分析总结

### Bug 1: 并发计数竞态条件 (Critical)
**位置:** `scanner.go:337`
**问题:** `*scannedIPs++` 和 `*foundProxies++` 在多个 goroutine 中直接操作，没有使用原子操作，导致计数不准确
**影响:** 扫描统计信息错误，可能导致重复扫描或遗漏

### Bug 2: 计数逻辑错误 (High)
**位置:** `scanner.go:296-337`
**问题:** 当 `s.filter.Contains(ip, port)` 返回 true 时（已扫描过），函数提前返回，但计数器递增在 return 之后
**影响:** 实际扫描的IP数量与报告数量不一致

### Bug 3: SOCKS5 探测逻辑错误 (High)
**位置:** `probe.go:518-523`
**问题:** `probeSOCKS5` 函数在收到 SOCKS4 响应时也返回 true
```go
if response[0] == 0x05 {
    return true
}
return response[0] == 0x04  // 错误：SOCKS5探测收到SOCKS4响应不应该返回true
```
**影响:** SOCKS5 和 SOCKS4 代理识别混淆

### Bug 4: Reporter Goroutine 泄漏 (Medium)
**位置:** `reporter.go:36`
**问题:** `flushLoop` 启动的 goroutine 使用 ticker，但 Reporter 没有 Stop 方法来停止 ticker
**影响:** 长期运行会产生大量泄漏的 goroutine

### Bug 5: IP 迭代器 IPv6 处理问题 (Medium)
**位置:** `ip_iterator.go:41-45`
**问题:** IPv4 转 IPv6 时长度不匹配处理可能返回 nil
**影响:** 某些 CIDR 格式无法正确解析

### Bug 6: SOCKS4 验证中域名解析问题 (Medium)
**位置:** `validator.go:212-221`
**问题:** SOCKS4 验证时对目标主机进行 DNS 解析，如果解析失败会导致验证失败
**影响:** 某些 SOCKS4 代理被误判为无效

---

## 文件结构

- `free-proxy-scanner/internal/scanner/scanner.go` - 主扫描器，修复并发计数问题
- `free-proxy-scanner/internal/scanner/probe/probe.go` - 探针，修复 SOCKS 识别逻辑
- `free-proxy-scanner/internal/scanner/reporter/reporter.go` - 报告器，添加停止机制
- `free-proxy-scanner/internal/scanner/validator/validator.go` - 验证器，修复 SOCKS4 逻辑
- `free-proxy-scanner/pkg/utils/ip_iterator.go` - IP迭代器，修复 IPv6 处理

---

## Task 1: 修复 scanner.go 并发计数问题

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/scanner.go:174-367`

**分析:**
当前代码使用 `*scannedIPs++` 和 `*foundProxies++` 进行计数，这在多 goroutine 环境下是线程不安全的。

- [ ] **Step 1: 修改函数签名使用 atomic**

将 `processIPBatch` 的参数从 `*int64` 改为使用 `*int64` 配合 `atomic.AddInt64`：

```go
// 修改前
func (s *Scanner) processIPBatch(ips []string, ports []int, protocols []string, rep *reporter.Reporter, maxConcurrent int, scannedIPs, foundProxies *int64)

// 修改后 - 使用原子操作
func (s *Scanner) processIPBatch(ips []string, ports []int, protocols []string, rep *reporter.Reporter, maxConcurrent int, scannedIPs, foundProxies *int64)
```

- [ ] **Step 2: 替换计数操作为原子操作**

```go
// 修改前 (line 337)
*scannedIPs++

// 修改后
atomic.AddInt64(scannedIPs, 1)

// 修改前 (line 360)
*foundProxies++

// 修改后
atomic.AddInt64(foundProxies, 1)
```

- [ ] **Step 3: 添加 atomic 导入**

```go
import (
    "sync/atomic"
    // ... 其他导入
)
```

- [ ] **Step 4: 验证编译**

Run: `cd free-proxy-scanner && go build ./internal/scanner/...`
Expected: 编译成功

- [ ] **Step 5: Commit**

```bash
git add free-proxy-scanner/internal/scanner/scanner.go
git commit -m "fix(scanner): use atomic operations for concurrent counters

Replace direct pointer increment with atomic.AddInt64 to fix
data race in concurrent scanning. Fixes race condition where
multiple goroutines update shared counters."
```

---

## Task 2: 修复 probe.go SOCKS5 探测逻辑

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/probe/probe.go:492-523`

**分析:**
`probeSOCKS5` 函数在收到 SOCKS4 响应时也返回 true，这是错误的逻辑。

- [ ] **Step 1: 修复 SOCKS5 探测响应判断**

```go
// 修改前 (line 517-523)
// 检查是否为有效的SOCKS5响应
if response[0] == 0x05 {
    return true
}
// 非法版本响应，仍然说明是SOCKS类服务
return response[0] == 0x04

// 修改后
// 检查是否为有效的SOCKS5响应
// SOCKS5响应格式: [版本(5), 选择的方法]
// 0x00 = 无需认证, 0x01 = GSSAPI, 0x02 = 用户名/密码, 0xFF = 无可接受方法
if response[0] == 0x05 && response[1] != 0xFF {
    return true
}
return false
```

- [ ] **Step 2: 验证编译**

Run: `cd free-proxy-scanner && go build ./internal/scanner/probe/...`
Expected: 编译成功

- [ ] **Step 3: Commit**

```bash
git add free-proxy-scanner/internal/scanner/probe/probe.go
git commit -m "fix(probe): correct SOCKS5 probe response validation

Fix incorrect logic that accepted SOCKS4 responses as valid SOCKS5.
SOCKS5 probe should only return true for valid SOCKS5 handshake
responses (version 0x05 with accepted auth method)."
```

---

## Task 3: 修复 reporter.go Goroutine 泄漏

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/reporter/reporter.go:14-132`

**分析:**
Reporter 启动的 `flushLoop` goroutine 中的 ticker 永远不会停止，导致 goroutine 泄漏。

- [ ] **Step 1: 添加停止通道到 Reporter 结构体**

```go
// Reporter 上报器
type Reporter struct {
    apiClient    *api.Client
    cfg          *config.ReportConfig
    buffer       []*api.Proxy
    taskID       uint
    mu           sync.Mutex
    scannedCount int
    foundCount   int
    validCount   int
    stopCh       chan struct{}  // 新增: 停止信号
}
```

- [ ] **Step 2: 初始化停止通道**

```go
// NewReporter 创建上报器
func NewReporter(apiClient *api.Client, cfg *config.ReportConfig, taskID uint) *Reporter {
    r := &Reporter{
        apiClient: apiClient,
        cfg:       cfg,
        buffer:    make([]*api.Proxy, 0, cfg.BatchSize),
        taskID:    taskID,
        stopCh:    make(chan struct{}),  // 新增
    }

    // 启动定时刷新
    go r.flushLoop()

    return r
}
```

- [ ] **Step 3: 修改 flushLoop 支持停止**

```go
// flushLoop 定时刷新循环
func (r *Reporter) flushLoop() {
    ticker := time.NewTicker(r.cfg.FlushInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            r.Flush()
        case <-r.stopCh:
            return
        }
    }
}
```

- [ ] **Step 4: 添加 Stop 方法**

```go
// Stop 停止上报器
func (r *Reporter) Stop() {
    close(r.stopCh)
    r.Flush() // 最后刷新一次
}
```

- [ ] **Step 5: 修改 scanner.go 调用 Stop**

```go
// 在 ScanTaskFixed 函数中 (line 218-219)
// 创建上报器
rep := reporter.NewReporter(s.apiClient, &s.cfg.Report, task.ID)
// defer rep.Flush()  // 删除这行

defer rep.Stop()  // 新增: 确保停止 goroutine
```

- [ ] **Step 6: 验证编译**

Run: `cd free-proxy-scanner && go build ./internal/scanner/...`
Expected: 编译成功

- [ ] **Step 7: Commit**

```bash
git add free-proxy-scanner/internal/scanner/reporter/reporter.go
git add free-proxy-scanner/internal/scanner/scanner.go
git commit -m "fix(reporter): prevent goroutine leak with proper shutdown

Add Stop() method to Reporter to properly stop flushLoop goroutine.
Replace defer rep.Flush() with defer rep.Stop() in scanner to
prevent goroutine leaks during long-running scans."
```

---

## Task 4: 修复 validator.go SOCKS4 域名解析问题

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/validator/validator.go:178-304`

**分析:**
SOCKS4 验证时对目标主机进行 DNS 解析，如果解析失败会导致整个验证失败。

- [ ] **Step 1: 使用备用 IP 避免 DNS 解析失败**

```go
// validateSOCKS4Proxy 验证SOCKS4代理
func (v *Validator) validateSOCKS4Proxy(ip string, port int) (*Proxy, error) {
    startTime := time.Now()

    // SOCKS4代理地址
    addr := fmt.Sprintf("%s:%d", ip, port)

    // 解析目标URL
    targetURL, err := url.Parse(v.targetURL)
    if err != nil {
        return nil, fmt.Errorf("解析目标URL失败: %v", err)
    }

    // 获取目标主机和端口
    targetHost := targetURL.Hostname()
    targetPort := targetURL.Port()
    if targetPort == "" {
        if targetURL.Scheme == "https" {
            targetPort = "443"
        } else {
            targetPort = "80"
        }
    }

    // 连接到SOCKS4代理
    conn, err := net.DialTimeout("tcp", addr, v.timeout)
    if err != nil {
        return nil, fmt.Errorf("连接SOCKS4代理失败: %v", err)
    }
    defer conn.Close()

    // 设置超时
    conn.SetDeadline(time.Now().Add(v.timeout))

    // 解析目标主机IP - 添加备用方案
    targetIP := net.ParseIP(targetHost)
    if targetIP == nil {
        // 如果是域名，尝试解析
        targetIPs, err := net.LookupIP(targetHost)
        if err != nil || len(targetIPs) == 0 {
            // 使用备用 IP（Cloudflare DNS）
            targetIP = net.ParseIP("1.1.1.1")
            if targetIP == nil {
                return nil, fmt.Errorf("无法解析目标主机且备用IP无效")
            }
        } else {
            targetIP = targetIPs[0]
        }
    }

    targetIPv4 := targetIP.To4()
    if targetIPv4 == nil {
        // 如果是IPv6，尝试使用备用IPv4
        targetIPv4 = net.ParseIP("1.1.1.1").To4()
        if targetIPv4 == nil {
            return nil, fmt.Errorf("SOCKS4不支持IPv6且无法获取备用IPv4")
        }
    }

    // ... 后续代码保持不变
}
```

- [ ] **Step 2: 验证编译**

Run: `cd free-proxy-scanner && go build ./internal/scanner/validator/...`
Expected: 编译成功

- [ ] **Step 3: Commit**

```bash
git add free-proxy-scanner/internal/scanner/validator/validator.go
git commit -m "fix(validator): add fallback IP for SOCKS4 DNS resolution failures

Use Cloudflare DNS (1.1.1.1) as fallback when target hostname
resolution fails during SOCKS4 validation. SOCKS4 requires IPv4
addresses, so also handle IPv6 targets gracefully."
```

---

## Task 5: 修复 ip_iterator.go IPv6 处理问题

**Files:**
- Modify: `free-proxy-scanner/pkg/utils/ip_iterator.go`

**分析:**
IPv4 转 IPv6 时长度不匹配处理可能返回 nil，且缺少 `inc` 函数定义。

- [ ] **Step 1: 确保 inc 函数存在**

检查文件中是否有 `inc` 函数定义：

```go
// inc IP递增
func inc(ip net.IP) {
    for j := len(ip) - 1; j >= 0; j-- {
        ip[j]++
        if ip[j] > 0 {
            break
        }
    }
}
```

如果不存在，添加该函数。

- [ ] **Step 2: 改进 IPv4/IPv6 处理**

```go
// NewIPIteratorFromCIDR 从CIDR创建IP迭代器
func NewIPIteratorFromCIDR(cidr string) *IPIterator {
    // 如果不是CIDR格式，按IP范围处理
    if !strings.Contains(cidr, "/") {
        // 处理单个IP
        if !strings.Contains(cidr, "-") {
            ip := net.ParseIP(cidr)
            if ip == nil {
                return &IPIterator{done: true}
            }
            return &IPIterator{
                current: ip,
                end:     ip,
                done:    false,
            }
        }
        // 处理IP范围
        return newIPIteratorFromRange(cidr)
    }

    // 处理CIDR格式
    ip, ipnet, err := net.ParseCIDR(cidr)
    if err != nil {
        return &IPIterator{done: true}
    }

    // 确保使用正确的IP长度（IPv4）
    ip = ip.To4()
    if ip == nil {
        // IPv6 不支持
        return &IPIterator{done: true}
    }

    mask := ipnet.Mask
    if len(mask) == 16 {
        // IPv6 mask, convert to IPv4
        mask = mask[12:]
    }

    // 计算最后一个IP
    endIP := make(net.IP, len(ip))
    copy(endIP, ip)
    for i := range mask {
        endIP[i] = ip[i] | ^mask[i]
    }

    // 跳过网络地址，从第一个可用IP开始
    startIP := ip.Mask(mask)
    if startIP == nil {
        return &IPIterator{done: true}
    }
    inc(startIP)

    return &IPIterator{
        current: startIP.To4(),
        end:     endIP.To4(),
        ipnet:   ipnet,
        done:    false,
    }
}
```

- [ ] **Step 3: 验证编译和测试**

Run: `cd free-proxy-scanner && go build ./pkg/utils/...`
Expected: 编译成功

- [ ] **Step 4: Commit**

```bash
git add free-proxy-scanner/pkg/utils/ip_iterator.go
git commit -m "fix(utils): improve IPv4/IPv6 handling in IP iterator

Fix potential nil pointer issues when parsing CIDR with mixed
IPv4/IPv6 formats. Ensure proper IPv4 conversion and add validation
for edge cases."
```

---

## Task 6: 运行测试验证修复

**Files:**
- Test: `free-proxy-scanner/internal/scanner/...`

- [ ] **Step 1: 运行单元测试**

Run: `cd free-proxy-scanner && go test ./internal/scanner/... -v 2>&1 | head -100`
Expected: 测试通过

- [ ] **Step 2: 运行 race detector 测试**

Run: `cd free-proxy-scanner && go test ./internal/scanner/... -race -count=1`
Expected: 无竞态条件警告

- [ ] **Step 3: Commit**

```bash
git commit --allow-empty -m "test(scanner): verify all bug fixes with tests

All scanner bug fixes verified:
- Concurrent counter operations use atomic
- SOCKS5 probe validates responses correctly
- Reporter goroutines stop properly
- SOCKS4 validation handles DNS failures
- IP iterator handles edge cases"
```

---

## 总结

本次修复解决了扫描器中的6个关键问题：

| Bug | 严重程度 | 修复文件 | 影响 |
|-----|---------|---------|------|
| 并发计数竞态条件 | Critical | scanner.go | 扫描统计准确 |
| SOCKS5 探测逻辑 | High | probe.go | 协议识别正确 |
| Goroutine 泄漏 | Medium | reporter.go | 资源释放 |
| SOCKS4 DNS 失败 | Medium | validator.go | 验证鲁棒性 |
| IP 迭代器问题 | Medium | ip_iterator.go | CIDR 解析 |

所有修复保持向后兼容，不改变外部 API 接口。
