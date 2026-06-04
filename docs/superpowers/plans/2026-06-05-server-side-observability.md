# Server-Side Scanner Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 在 API 服务端创建扫描器可观测体系：持久化心跳度量数据到数据库，提供仪表盘 API 供管理员实时查看扫描器状态、代理质量分布和扫描进度。

**Architecture:** Scanner 通过心跳上报 MetricsSnapshot → API Server 接收并存入 `scanner_metrics` 时序表 → 仪表盘 API 查询最新指标和历史趋势 → 前端展示扫描器在线状态、代理数量分布、延迟热力图。使用 MySQL 存储时序数据（每次心跳 INSERT 一行），GORM 做 ORM，gin 做 HTTP 框架，与现有 API Server 项目结构一致。

**Tech Stack:** Go 1.22, Gin 1.9, GORM 1.25, MySQL 8.0

**Risks:**
- API Server 子模块为私有仓库无法推送 → 缓解：在本地目录创建完整项目，后续手动推送
- 心跳频率 30s 产生大量时序数据 → 缓解：设计数据保留策略，7天以上自动清理
- 数据库表结构与现有表可能冲突 → 缓解：使用独立新表，不修改现有表

---

### Task 1: 初始化 API Server 项目骨架 + GORM 模型

**Depends on:** None
**Files:**
- Create: `free-proxy-hunter-api-server/go.mod`
- Create: `free-proxy-hunter-api-server/cmd/server/main.go`
- Create: `free-proxy-hunter-api-server/internal/model/scanner.go`
- Create: `free-proxy-hunter-api-server/internal/model/scanner_metric.go`
- Create: `free-proxy-hunter-api-server/internal/model/proxy.go`
- Create: `free-proxy-hunter-api-server/internal/model/scan_task.go`
- Create: `free-proxy-hunter-api-server/configs/config.example.yaml`

- [ ] **Step 1: 初始化 Go Module 和安装依赖**

```bash
cd free-proxy-hunter-api-server
go mod init github.com/free-proxy-hunter/free-proxy-hunter-api-server
go get github.com/gin-gonic/gin@v1.9.1
go get gorm.io/gorm@v1.25.12
go get gorm.io/driver/mysql@v1.5.7
go get github.com/spf13/viper@v1.18.2
```

- [ ] **Step 2: 创建配置文件模板**

```yaml
# configs/config.example.yaml
server:
  port: 53361
  mode: release  # debug / release / test

database:
  host: 127.0.0.1
  port: 3306
  username: root
  password: ""
  dbname: free_proxy_hunter
  charset: utf8mb4
  max_idle_conns: 10
  max_open_conns: 100

scanner:
  heartbeat_retention_days: 30
  metric_retention_days: 7
```

- [ ] **Step 3: 创建 Scanner 模型 — 扫描器注册信息**

```go
// internal/model/scanner.go
package model

import "time"

// Scanner 扫描器注册信息
type Scanner struct {
	ID          uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	ScannerID   string    `gorm:"uniqueIndex;size:64;not null" json:"scanner_id"`
	Name        string    `gorm:"size:128" json:"name"`
	Hostname    string    `gorm:"size:128" json:"hostname"`
	OS          string    `gorm:"size:32" json:"os"`
	Arch        string    `gorm:"size:32" json:"arch"`
	CPUCount    int       `json:"cpu_count"`
	MemoryTotal int64     `json:"memory_total"`
	Version     string    `gorm:"size:32" json:"version"`
	Status      string    `gorm:"size:32;default:offline" json:"status"` // online/offline
	LastSeenAt  time.Time `json:"last_seen_at"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
```

- [ ] **Step 4: 创建 ScannerMetric 模型 — 心跳度量时序数据**

```go
// internal/model/scanner_metric.go
package model

import "time"

// ScannerMetric 扫描器度量时序数据，每次心跳插入一行
type ScannerMetric struct {
	ID                uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	ScannerID         string    `gorm:"index;size:64;not null" json:"scanner_id"`
	PortsScanned      int64     `json:"ports_scanned"`
	PortsOpen         int64     `json:"ports_open"`
	ProxiesValidated  int64     `json:"proxies_validated"`
	ProxiesPostValid  int64     `json:"proxies_post_valid"`
	ProxiesFailed     int64     `json:"proxies_failed"`
	IPsScanned        int64     `json:"ips_scanned"`
	TasksCompleted    int64     `json:"tasks_completed"`
	TasksFailed       int64     `json:"tasks_failed"`
	HTTPProxies       int64     `json:"http_proxies"`
	SOCKS4Proxies     int64     `json:"socks4_proxies"`
	SOCKS5Proxies     int64     `json:"socks5_proxies"`
	TransparentProxies int64    `json:"transparent_proxies"`
	AnonymousProxies  int64     `json:"anonymous_proxies"`
	EliteProxies      int64     `json:"elite_proxies"`
	UnknownAnonProxies int64    `json:"unknown_anon_proxies"`
	AvgLatencyMs      int64     `json:"avg_latency_ms"`
	MaxLatencyMs      int64     `json:"max_latency_ms"`
	MinLatencyMs      int64     `json:"min_latency_ms"`
	P50LatencyMs      int64     `json:"p50_latency_ms"`
	P95LatencyMs      int64     `json:"p95_latency_ms"`
	P99LatencyMs      int64     `json:"p99_latency_ms"`
	UptimeSeconds     int64     `json:"uptime_seconds"`
	RecordedAt        time.Time `gorm:"index" json:"recorded_at"`
}

// TableName 指定表名
func (ScannerMetric) TableName() string {
	return "scanner_metrics"
}
```

- [ ] **Step 5: 创建 Proxy 模型**

```go
// internal/model/proxy.go
package model

import "time"

// Proxy 代理信息
type Proxy struct {
	ID           uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	IP           string    `gorm:"index;size:45;not null" json:"ip"`
	Port         int       `gorm:"not null" json:"port"`
	Protocol     string    `gorm:"size:16;not null" json:"protocol"`
	Country      string    `gorm:"size:8" json:"country"`
	Region       string    `gorm:"size:64" json:"region"`
	City         string    `gorm:"size:64" json:"city"`
	Latitude     float64   `json:"latitude"`
	Longitude    float64   `json:"longitude"`
	Anonymity    string    `gorm:"size:16" json:"anonymity"`
	Speed        int       `json:"speed"`
	Status       string    `gorm:"size:32;default:available" json:"status"`
	RequireAuth  bool      `json:"require_auth"`
	AuthUsername string    `gorm:"size:64" json:"auth_username,omitempty"`
	AuthPassword string    `gorm:"size:64" json:"auth_password,omitempty"`
	TaskID       uint      `gorm:"index" json:"task_id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// TableName 指定表名
func (Proxy) TableName() string {
	return "proxies"
}
```

- [ ] **Step 6: 创建 ScanTask 模型**

```go
// internal/model/scan_task.go
package model

import "time"

// ScanTask 扫描任务
type ScanTask struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Name      string    `gorm:"size:128" json:"name"`
	IPRanges  string    `gorm:"type:text" json:"ip_ranges"`
	Ports     string    `gorm:"size:512" json:"ports"`
	Protocols string    `gorm:"size:128" json:"protocols"`
	Priority  int       `gorm:"default:0" json:"priority"`
	Status    string    `gorm:"size:32;index;default:pending" json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 指定表名
func (ScanTask) TableName() string {
	return "scan_tasks"
}
```

- [ ] **Step 7: 创建 main.go 入口**

```go
// cmd/server/main.go
package main

import (
	"fmt"
	"log"

	"github.com/free-proxy-hunter/free-proxy-hunter-api-server/internal/model"
	"github.com/free-proxy-hunter/free-proxy-hunter-api-server/internal/router"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func main() {
	// 初始化数据库
	dsn := "root:@tcp(127.0.0.1:3306)/free_proxy_hunter?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("连接数据库失败: %v", err)
	}

	// 自动迁移
	if err := db.AutoMigrate(
		&model.Scanner{},
		&model.ScannerMetric{},
		&model.Proxy{},
		&model.ScanTask{},
	); err != nil {
		log.Fatalf("数据库迁移失败: %v", err)
	}
	fmt.Println("数据库迁移完成")

	// 初始化路由
	r := router.Setup(db)

	// 启动服务
	fmt.Println("API 服务器启动在 :53361")
	if err := r.Run(":53361"); err != nil {
		log.Fatalf("启动服务失败: %v", err)
	}
}
```

- [ ] **Step 8: 验证项目可构建**
Run: `cd free-proxy-hunter-api-server && go build ./...`
Expected:
  - Exit code: 0 (可能有未实现的 import 错误，后续 Task 修复)

- [ ] **Step 9: 提交**
Run: `cd free-proxy-hunter-api-server && git init && git add -A && git commit -m "feat(api-server): initialize project with GORM models for scanner observability

- Scanner model for registration info
- ScannerMetric model for heartbeat time-series data
- Proxy model with anonymity field
- ScanTask model
- MySQL auto-migration on startup

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`

---

### Task 2: 实现心跳处理 + 度量存储

**Depends on:** Task 1
**Files:**
- Create: `free-proxy-hunter-api-server/internal/handler/heartbeat.go`
- Create: `free-proxy-hunter-api-server/internal/handler/register.go`
- Create: `free-proxy-hunter-api-server/internal/router/router.go`
- Create: `free-proxy-hunter-api-server/pkg/response/response.go`

- [ ] **Step 1: 创建统一响应包**

```go
// pkg/response/response.go
package response

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Response API 统一响应结构
type Response struct {
	Code      int         `json:"code"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data"`
	Timestamp int64       `json:"timestamp"`
}

// Success 成功响应
func Success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, Response{
		Code:      0,
		Message:   "success",
		Data:      data,
		Timestamp: time.Now().Unix(),
	})
}

// Error 错误响应
func Error(c *gin.Context, code int, message string) {
	c.JSON(http.StatusOK, Response{
		Code:      code,
		Message:   message,
		Data:      nil,
		Timestamp: time.Now().Unix(),
	})
}
```

- [ ] **Step 2: 创建心跳处理器 — 保存度量时序数据**

```go
// internal/handler/heartbeat.go
package handler

import (
	"time"

	"github.com/free-proxy-hunter/free-proxy-hunter-api-server/internal/model"
	"github.com/free-proxy-hunter/free-proxy-hunter-api-server/pkg/response"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// HeartbeatRequest 心跳请求（与 scanner 端定义一致）
type HeartbeatRequest struct {
	ScannerID         string  `json:"scanner_id" binding:"required"`
	Status            string  `json:"status"`
	TaskCount         int     `json:"task_count"`
	CPUUsage          float64 `json:"cpu_usage"`
	MemoryUsage       float64 `json:"memory_usage"`
	NetworkTraffic    int64   `json:"network_traffic"`
	PortsScanned      int64   `json:"ports_scanned"`
	ProxiesValidated  int64   `json:"proxies_validated"`
	ProxiesPostValid  int64   `json:"proxies_post_valid"`
	ProxiesFailed     int64   `json:"proxies_failed"`
	IPsScanned        int64   `json:"ips_scanned"`
	TasksCompleted    int64   `json:"tasks_completed"`
	HTTPProxies       int64   `json:"http_proxies"`
	SOCKS4Proxies     int64   `json:"socks4_proxies"`
	SOCKS5Proxies     int64   `json:"socks5_proxies"`
	TransparentProxies int64  `json:"transparent_proxies"`
	AnonymousProxies  int64   `json:"anonymous_proxies"`
	EliteProxies      int64   `json:"elite_proxies"`
	AvgLatencyMs      int64   `json:"avg_latency_ms"`
	P95LatencyMs      int64   `json:"p95_latency_ms"`
	UptimeSeconds     int64   `json:"uptime_seconds"`
}

// HeartbeatHandler 心跳处理器
type HeartbeatHandler struct {
	db *gorm.DB
}

// NewHeartbeatHandler 创建心跳处理器
func NewHeartbeatHandler(db *gorm.DB) *HeartbeatHandler {
	return &HeartbeatHandler{db: db}
}

// Handle 处理心跳请求
func (h *HeartbeatHandler) Handle(c *gin.Context) {
	var req HeartbeatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, 400, "请求参数错误: "+err.Error())
		return
	}

	// 1. 更新 Scanner 状态
	h.db.Model(&model.Scanner{}).
		Where("scanner_id = ?", req.ScannerID).
		Updates(map[string]interface{}{
			"status":       "online",
			"last_seen_at": time.Now(),
		})

	// 2. 保存度量时序数据
	metric := model.ScannerMetric{
		ScannerID:          req.ScannerID,
		PortsScanned:       req.PortsScanned,
		PortsOpen:          0, // 心跳中没有此字段，从增量计算
		ProxiesValidated:   req.ProxiesValidated,
		ProxiesPostValid:   req.ProxiesPostValid,
		ProxiesFailed:      req.ProxiesFailed,
		IPsScanned:         req.IPsScanned,
		TasksCompleted:     req.TasksCompleted,
		HTTPProxies:        req.HTTPProxies,
		SOCKS4Proxies:      req.SOCKS4Proxies,
		SOCKS5Proxies:      req.SOCKS5Proxies,
		TransparentProxies: req.TransparentProxies,
		AnonymousProxies:   req.AnonymousProxies,
		EliteProxies:       req.EliteProxies,
		AvgLatencyMs:       req.AvgLatencyMs,
		P95LatencyMs:       req.P95LatencyMs,
		UptimeSeconds:      req.UptimeSeconds,
		RecordedAt:         time.Now(),
	}

	if err := h.db.Create(&metric).Error; err != nil {
		response.Error(c, 500, "保存度量数据失败")
		return
	}

	// 3. 异步清理过期度量数据（7天前）
	go h.cleanOldMetrics(req.ScannerID)

	response.Success(c, nil)
}

// cleanOldMetrics 清理过期度量数据
func (h *HeartbeatHandler) cleanOldMetrics(scannerID string) {
	cutoff := time.Now().AddDate(0, 0, -7)
	h.db.Where("scanner_id = ? AND recorded_at < ?", scannerID, cutoff).
		Delete(&model.ScannerMetric{})
}
```

- [ ] **Step 3: 创建注册处理器**

```go
// internal/handler/register.go
package handler

import (
	"time"

	"github.com/free-proxy-hunter/free-proxy-hunter-api-server/internal/model"
	"github.com/free-proxy-hunter/free-proxy-hunter-api-server/pkg/response"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// RegisterRequest 注册请求
type RegisterRequest struct {
	ScannerID   string `json:"scanner_id" binding:"required"`
	Name        string `json:"name"`
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	CPUCount    int    `json:"cpu_count"`
	MemoryTotal int64  `json:"memory_total"`
	Version     string `json:"version"`
}

// RegisterHandler 注册处理器
type RegisterHandler struct {
	db *gorm.DB
}

// NewRegisterHandler 创建注册处理器
func NewRegisterHandler(db *gorm.DB) *RegisterHandler {
	return &RegisterHandler{db: db}
}

// Handle 处理注册请求
func (h *RegisterHandler) Handle(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, 400, "请求参数错误: "+err.Error())
		return
	}

	scanner := model.Scanner{
		ScannerID:   req.ScannerID,
		Name:        req.Name,
		Hostname:    req.Hostname,
		OS:          req.OS,
		Arch:        req.Arch,
		CPUCount:    req.CPUCount,
		MemoryTotal: req.MemoryTotal,
		Version:     req.Version,
		Status:      "online",
		LastSeenAt:  time.Now(),
	}

	// Upsert: 如果已存在则更新
	result := h.db.Where("scanner_id = ?", req.ScannerID).FirstOrCreate(&scanner)
	if result.Error != nil {
		response.Error(c, 500, "注册失败")
		return
	}

	// 更新已有记录
	h.db.Model(&scanner).Updates(map[string]interface{}{
		"name":         req.Name,
		"hostname":     req.Hostname,
		"os":           req.OS,
		"arch":         req.Arch,
		"cpu_count":    req.CPUCount,
		"memory_total": req.MemoryTotal,
		"version":      req.Version,
		"status":       "online",
		"last_seen_at": time.Now(),
	})

	response.Success(c, scanner)
}
```

- [ ] **Step 4: 创建路由注册**

```go
// internal/router/router.go
package router

import (
	"github.com/free-proxy-hunter/free-proxy-hunter-api-server/internal/handler"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Setup 初始化路由
func Setup(db *gorm.DB) *gin.Engine {
	r := gin.Default()

	// 健康检查
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// API v1
	v1 := r.Group("/api/v1")
	{
		scanner := v1.Group("/scanner")
		{
			// 注册
			registerHandler := handler.NewRegisterHandler(db)
			scanner.POST("/register", registerHandler.Handle)

			// 心跳
			heartbeatHandler := handler.NewHeartbeatHandler(db)
			scanner.POST("/heartbeat", heartbeatHandler.Handle)
		}
	}

	return r
}
```

- [ ] **Step 5: 验证项目可构建**
Run: `cd free-proxy-hunter-api-server && go build ./...`
Expected:
  - Exit code: 0

- [ ] **Step 6: 提交**
Run: `cd free-proxy-hunter-api-server && git add -A && git commit -m "feat(api-server): implement heartbeat handler with metric persistence

- HeartbeatRequest matches scanner client definition exactly
- Each heartbeat inserts a ScannerMetric row for time-series analysis
- Update Scanner status to online on each heartbeat
- Async cleanup of metrics older than 7 days
- Register handler with upsert logic
- Unified response format matching scanner expectations

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`

---

### Task 3: 实现仪表盘 API — 管理端可观测查询接口

**Depends on:** Task 2
**Files:**
- Create: `free-proxy-hunter-api-server/internal/handler/dashboard.go`

- [ ] **Step 1: 创建仪表盘 API 处理器 — 提供管理员查看扫描器状态和度量数据的接口**

```go
// internal/handler/dashboard.go
package handler

import (
	"time"

	"github.com/free-proxy-hunter/free-proxy-hunter-api-server/internal/model"
	"github.com/free-proxy-hunter/free-proxy-hunter-api-server/pkg/response"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// DashboardHandler 仪表盘处理器
type DashboardHandler struct {
	db *gorm.DB
}

// NewDashboardHandler 创建仪表盘处理器
func NewDashboardHandler(db *gorm.DB) *DashboardHandler {
	return &DashboardHandler{db: db}
}

// ScannerStatus 扫描器状态摘要
type ScannerStatus struct {
	ScannerID   string `json:"scanner_id"`
	Name        string `json:"name"`
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	Version     string `json:"version"`
	Status      string `json:"status"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	UptimeSeconds int64 `json:"uptime_seconds"`
	// 最新度量
	ProxiesValidated int64 `json:"proxies_validated"`
	HTTPProxies      int64 `json:"http_proxies"`
	SOCKS4Proxies    int64 `json:"socks4_proxies"`
	SOCKS5Proxies    int64 `json:"socks5_proxies"`
	AvgLatencyMs     int64 `json:"avg_latency_ms"`
	P95LatencyMs     int64 `json:"p95_latency_ms"`
}

// ListScanners 列出所有扫描器状态
// GET /api/v1/dashboard/scanners
func (h *DashboardHandler) ListScanners(c *gin.Context) {
	var scanners []model.Scanner
	if err := h.db.Find(&scanners).Error; err != nil {
		response.Error(c, 500, "查询扫描器失败")
		return
	}

	// 将超时的扫描器标记为 offline
	now := time.Now()
	for i := range scanners {
		if now.Sub(scanners[i].LastSeenAt) > 2*time.Minute {
			scanners[i].Status = "offline"
		}
	}

	result := make([]ScannerStatus, 0, len(scanners))
	for _, s := range scanners {
		// 获取最新度量
		var latestMetric model.ScannerMetric
		h.db.Where("scanner_id = ?", s.ScannerID).
			Order("recorded_at DESC").First(&latestMetric)

		status := ScannerStatus{
			ScannerID:        s.ScannerID,
			Name:             s.Name,
			Hostname:         s.Hostname,
			OS:               s.OS,
			Version:          s.Version,
			Status:           s.Status,
			LastSeenAt:       s.LastSeenAt,
			UptimeSeconds:    latestMetric.UptimeSeconds,
			ProxiesValidated: latestMetric.ProxiesValidated,
			HTTPProxies:      latestMetric.HTTPProxies,
			SOCKS4Proxies:    latestMetric.SOCKS4Proxies,
			SOCKS5Proxies:    latestMetric.SOCKS5Proxies,
			AvgLatencyMs:     latestMetric.AvgLatencyMs,
			P95LatencyMs:     latestMetric.P95LatencyMs,
		}
		result = append(result, status)
	}

	response.Success(c, result)
}

// ScannerMetricHistory 扫描器度量历史
type ScannerMetricHistory struct {
	ScannerID string               `json:"scanner_id"`
	Metrics   []model.ScannerMetric `json:"metrics"`
}

// GetScannerMetrics 获取指定扫描器的度量历史
// GET /api/v1/dashboard/scanners/:id/metrics?hours=24
func (h *DashboardHandler) GetScannerMetrics(c *gin.Context) {
	scannerID := c.Param("id")
	hours := c.DefaultQuery("hours", "24")

	duration, err := time.ParseDuration(hours + "h")
	if err != nil {
		duration = 24 * time.Hour
	}

	since := time.Now().Add(-duration)
	var metrics []model.ScannerMetric
	if err := h.db.Where("scanner_id = ? AND recorded_at > ?", scannerID, since).
		Order("recorded_at ASC").Find(&metrics).Error; err != nil {
		response.Error(c, 500, "查询度量数据失败")
		return
	}

	response.Success(c, ScannerMetricHistory{
		ScannerID: scannerID,
		Metrics:   metrics,
	})
}

// ProxyDistribution 代理分布统计
type ProxyDistribution struct {
	ByProtocol  map[string]int64 `json:"by_protocol"`
	ByAnonymity map[string]int64 `json:"by_anonymity"`
	ByCountry   map[string]int64 `json:"by_country"`
	Total       int64            `json:"total"`
}

// GetProxyDistribution 获取代理分布统计
// GET /api/v1/dashboard/proxy-distribution
func (h *DashboardHandler) GetProxyDistribution(c *gin.Context) {
	var proxies []model.Proxy
	h.db.Where("status = ?", "available").Find(&proxies)

	dist := ProxyDistribution{
		ByProtocol:  make(map[string]int64),
		ByAnonymity: make(map[string]int64),
		ByCountry:   make(map[string]int64),
		Total:       int64(len(proxies)),
	}

	for _, p := range proxies {
		dist.ByProtocol[p.Protocol]++
		if p.Anonymity != "" {
			dist.ByAnonymity[p.Anonymity]++
		} else {
			dist.ByAnonymity["unknown"]++
		}
		if p.Country != "" {
			dist.ByCountry[p.Country]++
		}
	}

	response.Success(c, dist)
}

// ClusterMetrics 集群汇总度量
type ClusterMetrics struct {
	TotalScanners      int   `json:"total_scanners"`
	OnlineScanners     int   `json:"online_scanners"`
	OfflineScanners    int   `json:"offline_scanners"`
	TotalProxies       int64 `json:"total_proxies"`
	TotalPortsScanned  int64 `json:"total_ports_scanned"`
	TotalProxiesValid  int64 `json:"total_proxies_valid"`
	TotalProxiesFailed int64 `json:"total_proxies_failed"`
	AvgLatencyMs       int64 `json:"avg_latency_ms"`
}

// GetClusterMetrics 获取集群汇总度量
// GET /api/v1/dashboard/cluster-metrics
func (h *DashboardHandler) GetClusterMetrics(c *gin.Context) {
	var scanners []model.Scanner
	h.db.Find(&scanners)

	online := 0
	for _, s := range scanners {
		if time.Since(s.LastSeenAt) < 2*time.Minute {
			online++
		}
	}

	// 集群汇总：取每个 scanner 最新度量的总和
	var totalPortsScanned, totalProxiesValid, totalProxiesFailed, totalLatency, latencyCount int64
	for _, s := range scanners {
		var m model.ScannerMetric
		if err := h.db.Where("scanner_id = ?", s.ScannerID).
			Order("recorded_at DESC").First(&m).Error; err != nil {
			continue
		}
		totalPortsScanned += m.PortsScanned
		totalProxiesValid += m.ProxiesValidated
		totalProxiesFailed += m.ProxiesFailed
		if m.AvgLatencyMs > 0 {
			totalLatency += m.AvgLatencyMs
			latencyCount++
		}
	}

	var avgLatency int64
	if latencyCount > 0 {
		avgLatency = totalLatency / latencyCount
	}

	var totalProxies int64
	h.db.Model(&model.Proxy{}).Where("status = ?", "available").Count(&totalProxies)

	response.Success(c, ClusterMetrics{
		TotalScanners:      len(scanners),
		OnlineScanners:     online,
		OfflineScanners:    len(scanners) - online,
		TotalProxies:       totalProxies,
		TotalPortsScanned:  totalPortsScanned,
		TotalProxiesValid:  totalProxiesValid,
		TotalProxiesFailed: totalProxiesFailed,
		AvgLatencyMs:       avgLatency,
	})
}
```

- [ ] **Step 2: 注册仪表盘路由到 router.go**

文件: `free-proxy-hunter-api-server/internal/router/router.go`

在 `v1.Group` 中添加 dashboard 路由组：

```go
// 在 v1 组中添加
dashboard := v1.Group("/dashboard")
{
	dashHandler := handler.NewDashboardHandler(db)
	dashboard.GET("/scanners", dashHandler.ListScanners)
	dashboard.GET("/scanners/:id/metrics", dashHandler.GetScannerMetrics)
	dashboard.GET("/proxy-distribution", dashHandler.GetProxyDistribution)
	dashboard.GET("/cluster-metrics", dashHandler.GetClusterMetrics)
}
```

- [ ] **Step 3: 验证项目可构建**
Run: `cd free-proxy-hunter-api-server && go build ./...`
Expected:
  - Exit code: 0

- [ ] **Step 4: 提交**
Run: `cd free-proxy-hunter-api-server && git add -A && git commit -m "feat(api-server): add dashboard API for scanner observability

- GET /api/v1/dashboard/scanners — list all scanners with latest metrics
- GET /api/v1/dashboard/scanners/:id/metrics?hours=24 — metric history
- GET /api/v1/dashboard/proxy-distribution — proxy stats by protocol/anonymity/country
- GET /api/v1/dashboard/cluster-metrics — cluster-wide summary
- Auto-detect offline scanners (no heartbeat > 2min)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`

---

### Task 4: 实现 Report Handler + Task Handler

**Depends on:** Task 2
**Files:**
- Create: `free-proxy-hunter-api-server/internal/handler/report.go`
- Create: `free-proxy-hunter-api-server/internal/handler/task.go`
- Modify: `free-proxy-hunter-api-server/internal/router/router.go`

- [ ] **Step 1: 创建上报处理器 — 保存扫描结果和代理数据**

```go
// internal/handler/report.go
package handler

import (
	"github.com/free-proxy-hunter/free-proxy-hunter-api-server/internal/model"
	"github.com/free-proxy-hunter/free-proxy-hunter-api-server/pkg/response"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// ReportRequest 上报请求
type ReportRequest struct {
	TaskID       uint          `json:"task_id" binding:"required"`
	Proxies      []ProxyEntry  `json:"proxies"`
	ScannedCount int           `json:"scanned_count"`
	FoundCount   int           `json:"found_count"`
	ValidCount   int           `json:"valid_count"`
}

// ProxyEntry 代理条目（与 scanner 端 api.Proxy 一致）
type ProxyEntry struct {
	IP           string  `json:"ip"`
	Port         int     `json:"port"`
	Protocol     string  `json:"protocol"`
	Country      string  `json:"country"`
	Region       string  `json:"region"`
	City         string  `json:"city"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	Anonymity    string  `json:"anonymity"`
	Speed        int     `json:"speed"`
	Status       string  `json:"status"`
	RequireAuth  bool    `json:"require_auth"`
	AuthUsername string  `json:"auth_username,omitempty"`
	AuthPassword string  `json:"auth_password,omitempty"`
}

// ReportHandler 上报处理器
type ReportHandler struct {
	db *gorm.DB
}

// NewReportHandler 创建上报处理器
func NewReportHandler(db *gorm.DB) *ReportHandler {
	return &ReportHandler{db: db}
}

// Handle 处理上报请求
func (h *ReportHandler) Handle(c *gin.Context) {
	var req ReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, 400, "请求参数错误: "+err.Error())
		return
	}

	// 批量保存代理数据
	for _, p := range req.Proxies {
		proxy := model.Proxy{
			IP:           p.IP,
			Port:         p.Port,
			Protocol:     p.Protocol,
			Country:      p.Country,
			Region:       p.Region,
			City:         p.City,
			Latitude:     p.Latitude,
			Longitude:    p.Longitude,
			Anonymity:    p.Anonymity,
			Speed:        p.Speed,
			Status:       p.Status,
			RequireAuth:  p.RequireAuth,
			AuthUsername: p.AuthUsername,
			AuthPassword: p.AuthPassword,
			TaskID:       req.TaskID,
		}

		// Upsert: 同 IP+Port+Protocol 更新，否则插入
		h.db.Where("ip = ? AND port = ? AND protocol = ?", p.IP, p.Port, p.Protocol).
			Assign(proxy).FirstOrCreate(&proxy)
	}

	response.Success(c, gin.H{
		"saved_count": len(req.Proxies),
	})
}
```

- [ ] **Step 2: 创建任务处理器**

```go
// internal/handler/task.go
package handler

import (
	"github.com/free-proxy-hunter/free-proxy-hunter-api-server/internal/model"
	"github.com/free-proxy-hunter/free-proxy-hunter-api-server/pkg/response"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// TaskHandler 任务处理器
type TaskHandler struct {
	db *gorm.DB
}

// NewTaskHandler 创建任务处理器
func NewTaskHandler(db *gorm.DB) *TaskHandler {
	return &TaskHandler{db: db}
}

// GetTasks 获取待处理任务
// GET /api/v1/scanner/tasks
func (h *TaskHandler) GetTasks(c *gin.Context) {
	scannerID := c.Query("scanner_id")

	var tasks []model.ScanTask
	query := h.db.Where("status = ?", "pending").Order("priority DESC")

	if scannerID != "" {
		// 按 scanner_id 过滤（未来可扩展为任务分配）
		query = query.Limit(10)
	}

	if err := query.Find(&tasks).Error; err != nil {
		response.Error(c, 500, "查询任务失败")
		return
	}

	response.Success(c, tasks)
}

// UpdateTaskStatus 更新任务状态
// PUT /api/v1/scan-tasks/:id/status
func (h *TaskHandler) UpdateTaskStatus(c *gin.Context) {
	taskID := c.Param("id")

	var body struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.Error(c, 400, "请求参数错误")
		return
	}

	if err := h.db.Model(&model.ScanTask{}).Where("id = ?", taskID).
		Update("status", body.Status).Error; err != nil {
		response.Error(c, 500, "更新任务状态失败")
		return
	}

	response.Success(c, nil)
}
```

- [ ] **Step 3: 注册新路由到 router.go**

在 router.go 的 `v1` 组中添加：

```go
// 任务相关
taskHandler := handler.NewTaskHandler(db)
scanner.GET("/tasks", taskHandler.GetTasks)

// 上报
reportHandler := handler.NewReportHandler(db)
scanner.POST("/report", reportHandler.Handle)

// 任务状态更新（独立路径）
v1.PUT("/scan-tasks/:id/status", taskHandler.UpdateTaskStatus)
```

- [ ] **Step 4: 验证项目可构建**
Run: `cd free-proxy-hunter-api-server && go build ./...`
Expected:
  - Exit code: 0

- [ ] **Step 5: 提交**
Run: `cd free-proxy-hunter-api-server && git add -A && git commit -m "feat(api-server): implement report and task handlers

- Report handler: upsert proxies with anonymity field on each scan report
- Task handler: get pending tasks + update task status
- Match scanner client API contract exactly

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`

---

### Task 5: 端到端验证 — 构建测试 + 数据库迁移验证

**Depends on:** Task 3, Task 4
**Files:**
- Create: `free-proxy-hunter-api-server/internal/handler/dashboard_test.go`
- Create: `free-proxy-hunter-api-server/internal/handler/heartbeat_test.go`

- [ ] **Step 1: 创建心跳处理器测试**

```go
// internal/handler/heartbeat_test.go
package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/free-proxy-hunter/free-proxy-hunter-api-server/internal/model"
)

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("连接测试数据库失败: %v", err)
	}
	db.AutoMigrate(&model.Scanner{}, &model.ScannerMetric{})
	return db
}

func TestHeartbeatHandler_Success(t *testing.T) {
	db := setupTestDB(t)
	// 先注册一个 scanner
	db.Create(&model.Scanner{ScannerID: "test-scanner-1", Status: "offline"})

	handler := NewHeartbeatHandler(db)

	req := HeartbeatRequest{
		ScannerID:        "test-scanner-1",
		Status:           "online",
		PortsScanned:     1000,
		ProxiesValidated: 10,
		HTTPProxies:      5,
		SOCKS5Proxies:    5,
		EliteProxies:     8,
		AnonymousProxies: 2,
		AvgLatencyMs:     150,
		UptimeSeconds:    3600,
	}

	body, _ := json.Marshal(req)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/heartbeat", handler.Handle)

	w := httptest.NewRecorder()
	httpReq, _ := http.NewRequest("POST", "/heartbeat", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, httpReq)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 验证度量数据已保存
	var count int64
	db.Model(&model.ScannerMetric{}).Where("scanner_id = ?", "test-scanner-1").Count(&count)
	if count != 1 {
		t.Errorf("expected 1 metric row, got %d", count)
	}

	// 验证 scanner 状态已更新
	var scanner model.Scanner
	db.Where("scanner_id = ?", "test-scanner-1").First(&scanner)
	if scanner.Status != "online" {
		t.Errorf("expected scanner status=online, got %s", scanner.Status)
	}
}

func TestHeartbeatHandler_MissingScannerID(t *testing.T) {
	db := setupTestDB(t)
	handler := NewHeartbeatHandler(db)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/heartbeat", handler.Handle)

	w := httptest.NewRecorder()
	httpReq, _ := http.NewRequest("POST", "/heartbeat", bytes.NewReader([]byte(`{}`)))
	httpReq.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, httpReq)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"].(float64) != 400 {
		t.Errorf("expected code=400, got %v", resp["code"])
	}
}
```

- [ ] **Step 2: 创建仪表盘处理器测试**

```go
// internal/handler/dashboard_test.go
package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/free-proxy-hunter/free-proxy-hunter-api-server/internal/model"
)

func setupDashboardTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("连接测试数据库失败: %v", err)
	}
	db.AutoMigrate(&model.Scanner{}, &model.ScannerMetric{}, &model.Proxy{})
	return db
}

func TestListScanners_ReturnsAllScanners(t *testing.T) {
	db := setupDashboardTestDB(t)

	// 创建测试数据
	db.Create(&model.Scanner{ScannerID: "scanner-1", Name: "Scanner 1", Status: "online", LastSeenAt: time.Now()})
	db.Create(&model.Scanner{ScannerID: "scanner-2", Name: "Scanner 2", Status: "online", LastSeenAt: time.Now()})
	db.Create(&model.ScannerMetric{ScannerID: "scanner-1", ProxiesValidated: 50, HTTPProxies: 30, AvgLatencyMs: 100, RecordedAt: time.Now()})

	handler := NewDashboardHandler(db)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/dashboard/scanners", handler.ListScanners)

	w := httptest.NewRecorder()
	httpReq, _ := http.NewRequest("GET", "/dashboard/scanners", nil)
	r.ServeHTTP(w, httpReq)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	data := resp["data"].([]interface{})
	if len(data) != 2 {
		t.Errorf("expected 2 scanners, got %d", len(data))
	}
}

func TestGetClusterMetrics(t *testing.T) {
	db := setupDashboardTestDB(t)

	db.Create(&model.Scanner{ScannerID: "scanner-1", Status: "online", LastSeenAt: time.Now()})
	db.Create(&model.Scanner{ScannerID: "scanner-2", Status: "online", LastSeenAt: time.Now().Add(-5 * time.Minute)})
	db.Create(&model.ScannerMetric{ScannerID: "scanner-1", ProxiesValidated: 100, PortsScanned: 5000, AvgLatencyMs: 200, RecordedAt: time.Now()})
	db.Create(&model.Proxy{IP: "1.2.3.4", Port: 8080, Protocol: "http", Anonymity: "elite", Status: "available"})

	handler := NewDashboardHandler(db)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/dashboard/cluster-metrics", handler.GetClusterMetrics)

	w := httptest.NewRecorder()
	httpReq, _ := http.NewRequest("GET", "/dashboard/cluster-metrics", nil)
	r.ServeHTTP(w, httpReq)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	data := resp["data"].(map[string]interface{})
	if data["total_scanners"].(float64) != 2 {
		t.Errorf("expected 2 scanners, got %v", data["total_scanners"])
	}
	if data["online_scanners"].(float64) != 1 {
		t.Errorf("expected 1 online scanner, got %v", data["online_scanners"])
	}
}
```

- [ ] **Step 3: 安装 SQLite 测试依赖并运行测试**

```bash
cd free-proxy-hunter-api-server
go get gorm.io/driver/sqlite
go test ./internal/handler/ -v -count=1
```

Expected:
  - Exit code: 0
  - Output contains: "PASS"

- [ ] **Step 4: 运行全量构建验证**
Run: `cd free-proxy-hunter-api-server && go build -o free-proxy-hunter-api-server ./cmd/server/`
Expected:
  - Exit code: 0
  - Binary `free-proxy-hunter-api-server` created

- [ ] **Step 5: 提交**
Run: `cd free-proxy-hunter-api-server && git add -A && git commit -m "test(api-server): add handler tests with SQLite in-memory DB

- Heartbeat handler: test metric persistence and scanner status update
- Dashboard handler: test scanner listing and cluster metrics
- Use SQLite for test isolation
- Verify full build produces binary

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`
