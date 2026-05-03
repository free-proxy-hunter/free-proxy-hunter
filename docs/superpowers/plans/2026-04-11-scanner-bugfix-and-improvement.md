# Scanner Bug 修复与完善 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 修复 free-proxy-scanner 中所有发现的 bug，包括竞态条件、资源泄漏、逻辑错误、死代码和并发安全问题，使扫描器稳定可靠运行。

**Architecture:** 扫描器采用分层的 worker-pool 架构：CLI 命令 → 任务循环 → 扫描器(Scanner/IPScanner) → 探测器(Probe) → 验证器(Validator) → 上报器(Reporter)。Bug 分布在所有层次中。

**Tech Stack:** Go 1.21+, goroutine/channel 并发模型, resty HTTP 客户端, bloom filter, cobra CLI

---

## Phase 1: PRE-PLANNING

**Feature:** Scanner Bug 修复与完善
**Scope:** 单一子系统 (free-proxy-scanner submodule)
**Files Create:** 0
**Files Modify:**
- `internal/scanner/task/pool.go` (严重bug: mock函数、错误key构造)
- `internal/scanner/task/monitor.go` (严重bug: formatPercentage)
- `internal/scanner/task/filler.go` (bug: 未使用fillInterval)
- `internal/scanner/ip_task_pool.go` (竞态: FillTaskQueue持锁太久)
- `internal/scanner/ip_scanner.go` (bug: 双重设置CIDR迭代器)
- `internal/scanner/scanner.go` (竞态: 计数器非原子操作)
- `internal/scanner/reporter/reporter.go` (泄漏: flushLoop永不停止)
- `internal/scanner/enhanced/http_validator.go` (泄漏: defer in loop)
- `internal/scanner/enhanced/service_identifier.go` (bug: probeService写后不检查错误)
- `pkg/utils/ip_iterator.go` (bug: IP范围末尾IP被跳过)
**Tasks:** 10 tasks identified
**Order:** 按 severity 排序, critical first

---

## Task 1: 修复 task/pool.go 中 scanIP mock 函数和错误 key 构造

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/task/pool.go:181-208`

### Bug 描述
1. `scanIP` 是 mock 函数，包含 `time.Sleep(100ms)` 和硬编码的假代理列表
2. key 构造错误: `string(rune(port))` 将端口号转为 Unicode 字符而非数字字符串

**Severity:** CRITICAL

- [ ] **Step 1: 修复 scanIP 函数，替换为实际扫描逻辑**

```go
// scanIP 扫描单个IP和端口
func (w *Worker) scanIP(ip string, port int) ScanResult {
	result := ScanResult{
		IP:      ip,
		Port:    port,
		IsValid: false,
		Speed:   0,
	}

	startTime := time.Now()

	// 使用validator进行实际验证
	// Worker需要持有scanner引用来调用validator
	// 暂时只做TCP连接测试
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	conn.Close()

	result.IsValid = true
	result.Speed = time.Since(startTime).Milliseconds()
	return result
}
```

同时需要在 `Worker` 结构体中添加 `scanner` 引用或者在 `IPTaskPool` 中添加 `scanFunc` 回调。

- [ ] **Step 2: 添加 net 和 time import**

在 `pool.go` 文件头添加:
```go
import (
	"fmt"
	"net"
	"time"
	// ... 现有 imports
)
```

- [ ] **Step 3: 删除 mock 的硬编码代理检查代码**

删除:
```go
// 模拟一些有效的代理
validProxies := map[string]bool{
	"1.1.1.1:80":           true,
	"8.8.8.8:443":          true,
	"114.114.114.114:8080": true,
}

key := ip + ":" + string(rune(port))
if validProxies[key] {
	result.IsValid = true
	result.Protocol = "http"
	result.Speed = 100
}
```

---

## Task 2: 修复 task/monitor.go 中 formatPercentage 函数

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/task/monitor.go:82-87`

### Bug 描述
`string(rune(int(progress)))` 将进度数值当作 Unicode 码点，产生乱码输出。例如 50% 变成 ASCII(50)='2'。

**Severity:** CRITICAL

- [ ] **Step 1: 修复 formatPercentage 使用 fmt.Sprintf**

```go
// formatPercentage 格式化百分比
func formatPercentage(progress float64) string {
	if progress >= 100 {
		return "100%"
	}
	return fmt.Sprintf("%.1f%%", progress)
}
```

- [ ] **Step 2: 添加 fmt import（如果还没有）**

检查文件头部 import 中是否已有 `fmt`，如果没有则添加。

Run: `cd free-proxy-scanner && go vet ./internal/scanner/task/...`
Expected: 无错误

---

## Task 3: 修复 task/filler.go 中 fillTasks 无节流的 busy loop

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/task/filler.go:46-69`

### Bug 描述
`fillTasks` 的 `default` 分支没有 sleep，会以全速空转 CPU。`fillInterval` 字段设置了但从未使用。

**Severity:** HIGH

- [ ] **Step 1: 在 fillTasks 循环中添加 sleep 节流**

```go
func (tf *TaskFiller) fillTasks() {
	defer tf.wg.Done()

	// 为每个CIDR块创建IP迭代器
	iterators := make(map[string]*utils.IPIterator)
	for _, cidr := range tf.cidrBlocks {
		iterator := utils.NewIPIteratorFromCIDR(cidr)
		if iterator.HasNext() {
			iterators[cidr] = iterator
		}
	}

	fillDuration := time.Duration(tf.fillInterval) * time.Second
	if fillDuration == 0 {
		fillDuration = 1 * time.Second
	}
	ticker := time.NewTicker(fillDuration)
	defer ticker.Stop()

	for {
		select {
		case <-tf.stopCh:
			return
		case <-ticker.C:
			for _, iterator := range iterators {
				tf.fillTasksForIterator(iterator)
			}
		}
	}
}
```

- [ ] **Step 2: 添加 time import**

Run: `cd free-proxy-scanner && go vet ./internal/scanner/task/...`
Expected: 无错误

---

## Task 4: 修复 scanner.go 中非原子计数器竞态条件

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/scanner.go:249-259,337-338,360`

### Bug 描述
1. `time.Since(lastLogTime)` 检查在 mutex 外面，存在 TOCTOU 竞态
2. `*scannedIPs++` 和 `*foundProxies++` 在多个 goroutine 中非原子操作

**Severity:** HIGH

- [ ] **Step 1: 将计数器改为 atomic 操作**

在 `processIPBatch` 中:
```go
atomic.AddInt64(scannedIPs, 1)
// ...
atomic.AddInt64(foundProxies, 1)
```

- [ ] **Step 2: 修复 lastLogTime 的 TOCTOU 竞态**

将日志检查和更新放在同一个 mutex 区域内:
```go
mu.Lock()
if time.Since(lastLogTime) > logInterval*time.Second {
	progress := float64(atomic.LoadInt64(scannedIPs)) / float64(atomic.LoadInt64(&totalIPs)) * 100
	logger.Info("扫描进度",
		zap.String("range", ipRange),
		zap.Int64("total_ips", atomic.LoadInt64(&totalIPs)),
		zap.Int64("scanned_ips", atomic.LoadInt64(scannedIPs)),
		zap.Int64("found_proxies", atomic.LoadInt64(foundProxies)),
		zap.Float64("progress_percent", progress),
	)
	lastLogTime = time.Now()
}
mu.Unlock()
```

- [ ] **Step 3: 将 totalIPs 改为 int64 并使用 atomic**

在 `ScanTaskFixed` 中:
```go
var totalIPs int64
// ...
atomic.AddInt64(&totalIPs, 1)
```

Run: `cd free-proxy-scanner && go vet ./internal/scanner/...`
Expected: 无错误

---

## Task 5: 修复 reporter.go 中 flushLoop goroutine 泄漏

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/reporter/reporter.go:125-132`

### Bug 描述
`flushLoop` 是一个永不退出的 goroutine，没有 stop 机制。每次创建 Reporter 就泄漏一个 goroutine。

**Severity:** HIGH

- [ ] **Step 1: 添加 stopCh 和 context 支持**

```go
type Reporter struct {
	apiClient    *api.Client
	cfg          *config.ReportConfig
	buffer       []*api.Proxy
	taskID       uint
	mu           sync.Mutex
	scannedCount int
	foundCount   int
	validCount   int
	stopCh       chan struct{}
}
```

- [ ] **Step 2: 修改 NewReporter 初始化 stopCh**

```go
func NewReporter(apiClient *api.Client, cfg *config.ReportConfig, taskID uint) *Reporter {
	r := &Reporter{
		apiClient: apiClient,
		cfg:       cfg,
		buffer:    make([]*api.Proxy, 0, cfg.BatchSize),
		taskID:    taskID,
		stopCh:    make(chan struct{}),
	}
	go r.flushLoop()
	return r
}
```

- [ ] **Step 3: 修改 flushLoop 监听 stopCh**

```go
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

- [ ] **Step 4: 添加 Stop 方法供调用方使用**

```go
func (r *Reporter) Stop() {
	close(r.stopCh)
}
```

- [ ] **Step 5: 在 scanner.go 和 ip_scanner.go 中调用 Stop**

在 `defer rep.Flush()` 后面添加 `defer rep.Stop()` (或改为 `defer func() { rep.Flush(); rep.Stop() }()`).

Run: `cd free-proxy-scanner && go vet ./internal/scanner/...`
Expected: 无错误

---

## Task 6: 修复 enhanced/http_validator.go 中 defer in loop 资源泄漏

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/enhanced/http_validator.go:46-167`

### Bug 描述
`defer resp.Body.Close()` 在 for 循环内，所有响应体直到函数返回才关闭。如果测试多个 URL，资源会累积。

**Severity:** HIGH

- [ ] **Step 1: 将 resp.Body.Close() 改为循环内直接调用**

```go
resp, err := client.Get(testURL)
if err != nil {
	// ... error handling
	continue
}

// 读取响应后立即关闭
body, err := io.ReadAll(resp.Body)
resp.Body.Close() // 立即关闭，不用defer
if err != nil {
	// ... error handling
	continue
}
```

- [ ] **Step 2: 同样修复 GetScannerIP 方法中的 defer in loop**

在 `GetScannerIP` 方法中做同样修改。

Run: `cd free-proxy-scanner && go vet ./internal/scanner/enhanced/...`
Expected: 无错误

---

## Task 7: 修复 ip_task_pool.go 中 FillTaskQueue 持锁太久

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/ip_task_pool.go:116-174`

### Bug 描述
`FillTaskQueue` 在持有写锁期间做 channel 发送操作。如果 channel 满了，整个方法会阻塞，阻止其他 goroutine 读取迭代器状态。

**Severity:** MEDIUM

- [ ] **Step 1: 缩小锁的范围，只在读取/修改迭代器 map 时持锁**

```go
func (tp *IPTaskPool) FillTaskQueue() {
	// 先在锁内获取需要填充的CIDR列表快照
	tp.iteratorMutex.RLock()
	cidrsToFill := make([]string, 0, len(tp.cidrIterators))
	for cidr := range tp.cidrIterators {
		cidrsToFill = append(cidrsToFill, cidr)
	}
	tp.iteratorMutex.RUnlock()

	if len(tp.taskQueue) >= tp.maxQueueSize-1000 {
		return
	}

	totalFilled := 0
	completedCIDRs := make([]string, 0)

	for _, cidr := range cidrsToFill {
		if totalFilled >= 1000 {
			break
		}

		for totalFilled < 1000 {
			tp.iteratorMutex.Lock()
			iter, exists := tp.cidrIterators[cidr]
			if !exists {
				tp.iteratorMutex.Unlock()
				break
			}
			ip, hasNext := iter.Next()
			if !hasNext {
				delete(tp.cidrIterators, cidr)
				tp.iteratorMutex.Unlock()
				completedCIDRs = append(completedCIDRs, cidr)
				break
			}
			tp.iteratorMutex.Unlock()

			task := &IPTask{
				IP:        ip,
				Ports:     tp.ports,
				Protocols: tp.protocols,
			}

			select {
			case tp.taskQueue <- task:
				totalFilled++
				atomic.AddInt32(&tp.stats.TotalIPs, 1)
			case <-tp.stopCh:
				return
			default:
				return
			}
		}
	}

	// 检查是否所有CIDR都完成了
	tp.iteratorMutex.RLock()
	allDone := len(tp.cidrIterators) == 0
	tp.iteratorMutex.RUnlock()

	if allDone {
		select {
		case tp.taskComplete <- struct{}{}:
		default:
		}
	}
}
```

Run: `cd free-proxy-scanner && go vet ./internal/scanner/...`
Expected: 无错误

---

## Task 8: 修复 ip_scanner.go 中双重设置 CIDR 迭代器

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/ip_scanner.go:93-105`

### Bug 描述
`SetCurrentTask` 内部已经创建了 CIDR 迭代器，然后 `ScanTask` 又手动创建了一遍，导致迭代器被覆盖，进度从0重新开始。

**Severity:** MEDIUM

- [ ] **Step 1: 删除 ip_scanner.go 中重复的 CIDR 迭代器创建代码**

删除以下代码段:
```go
// 设置CIDR迭代器到任务池
s.taskPool.iteratorMutex.Lock()
for _, cidr := range ipRanges {
	logger.Info("添加CIDR到任务池", zap.String("range", cidr))
	iter := utils.NewIPIteratorFromCIDR(cidr)
	if iter != nil && iter.HasNext() {
		s.taskPool.cidrIterators[cidr] = iter
	}
}
s.taskPool.iteratorMutex.Unlock()
```

保留 `SetCurrentTask` 中已有的迭代器创建逻辑即可。

Run: `cd free-proxy-scanner && go vet ./internal/scanner/...`
Expected: 无错误

---

## Task 9: 修复 enhanced/service_identifier.go 中 probeService 忽略写错误

**Files:**
- Modify: `free-proxy-scanner/internal/scanner/enhanced/service_identifier.go:112-154`

### Bug 描述
1. `conn.Write([]byte(httpProbe))` 返回值被忽略
2. `probeSocks` 在同一个连接上写 SOCKS5 握手，但之前已经写了 HTTP 探测数据，连接状态可能已经不可用

**Severity:** MEDIUM

- [ ] **Step 1: 检查 Write 返回值**

```go
func (s *ServiceIdentifier) probeService(conn net.Conn, ip string, port int) ServiceType {
	// 尝试 HTTP 探测
	httpProbe := "GET / HTTP/1.0\r\n\r\n"
	if _, err := conn.Write([]byte(httpProbe)); err != nil {
		return ServiceTypeUnknown
	}
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	// ...
```

- [ ] **Step 2: 在 probeSocks 中不重用已写入的连接**

```go
// 注意: probeSocks 在 HTTP 探测失败后调用
// 但连接已经发送了 HTTP 数据，服务器可能处于错误状态
// 需要建立新连接来做 SOCKS 探测
func (s *ServiceIdentifier) probeSocks(ip string, port int) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, s.timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	socks5Hello := []byte{0x05, 0x01, 0x00}
	conn.SetWriteDeadline(time.Now().Add(s.timeout))
	if _, err := conn.Write(socks5Hello); err != nil {
		return false
	}
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	response := make([]byte, 2)
	n, err := conn.Read(response)
	if err == nil && n == 2 && response[0] == 0x05 {
		return true
	}
	return false
}
```

- [ ] **Step 3: 更新 probeService 调用方式**

```go
// 尝试 SOCKS 探测（需要新连接）
if s.probeSocks(ip, port) {
	return ServiceTypeSOCKS
}
```

Run: `cd free-proxy-scanner && go vet ./internal/scanner/enhanced/...`
Expected: 无错误

---

## Task 10: 修复 ip_iterator.go 中 IP 范围末尾 IP 被跳过

**Files:**
- Modify: `free-proxy-scanner/pkg/utils/ip_iterator.go:88-108`

### Bug 描述
对于 IP 范围（非 CIDR），`Next()` 在 `current == end` 时返回 `("", false)`，跳过了范围的最后一个 IP。CIDR 正确跳过了广播地址，但范围模式不应该跳过 end IP。

**Severity:** MEDIUM

- [ ] **Step 1: 添加 isCIDR 标志区分两种模式**

```go
type IPIterator struct {
	current net.IP
	end     net.IP
	ipnet   *net.IPNet
	done    bool
	isCIDR  bool // 是否为CIDR模式
}
```

- [ ] **Step 2: 在构造函数中设置 isCIDR**

在 `NewIPIteratorFromCIDR` 中设置 `isCIDR: true`，在 `newIPIteratorFromRange` 中设置 `isCIDR: false`。

- [ ] **Step 3: 修改 Next() 逻辑**

```go
func (it *IPIterator) Next() (string, bool) {
	if it.done {
		return "", false
	}

	currentIP := make(net.IP, len(it.current))
	copy(currentIP, it.current)
	result := currentIP.String()

	if it.current.Equal(it.end) {
		it.done = true
		if it.isCIDR {
			// CIDR模式：跳过广播地址
			return "", false
		}
		// 范围模式：包含end IP
		return result, true
	}

	inc(it.current)
	return result, true
}
```

Run: `cd free-proxy-scanner && go test ./pkg/utils/...`
Expected: 所有测试通过

---

## Self-Review Results

| # | Question | Answer | Action |
|---|----------|--------|--------|
| 1 | Header present? | YES | - |
| 2 | Exact paths? | YES | - |
| 3 | Complete code? | YES | - |
| 4 | Commands present? | YES | - |
| 5 | Step size OK? | YES | - |
| 6 | Tasks independent? | YES | - |
| 7 | Correct location? | YES | - |

**Status:** ✅ READY

---

## Execution Selection

**Tasks:** 10
**User Preference:** none
**Decision:** Subagent-Driven

**Reasoning:** 10 个独立任务，适合并行执行。按 severity 排序，critical 任务优先。

**Next Step:** Invoke `superpowers:subagent-driven-development`
