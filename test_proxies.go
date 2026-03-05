package main

import (
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type Proxy struct {
	IP       string
	Port     int
	Protocol string
	Country  string
	Status   string
}

func main() {
	// 连接数据库
	db, err := sql.Open("mysql", "root:@tcp(localhost:3306)/free_proxy_hunter?charset=utf8mb4")
	if err != nil {
		fmt.Printf("数据库连接失败: %v\n", err)
		return
	}
	defer db.Close()

	// 查询所有代理
	rows, err := db.Query("SELECT ip, port, protocol, country, status FROM proxies")
	if err != nil {
		fmt.Printf("查询失败: %v\n", err)
		return
	}
	defer rows.Close()

	var proxies []Proxy
	for rows.Next() {
		var p Proxy
		err := rows.Scan(&p.IP, &p.Port, &p.Protocol, &p.Country, &p.Status)
		if err != nil {
			continue
		}
		proxies = append(proxies, p)
	}

	fmt.Printf("=== 开始测试 %d 个代理 ===\n\n", len(proxies))

	available := 0
	unavailable := 0
	authRequired := 0

	for i, p := range proxies {
		fmt.Printf("[%2d/%2d] 测试 %s:%d (%s/%s) ", i+1, len(proxies), p.IP, p.Port, p.Country, p.Status)

		result := testProxy(p.IP, p.Port)
		switch result {
		case "available":
			fmt.Printf("✅ 可用\n")
			available++
			// 更新数据库状态
			db.Exec("UPDATE proxies SET status='available', last_check_time=NOW() WHERE ip=? AND port=?", p.IP, p.Port)
		case "auth_required":
			fmt.Printf("🔒 需要认证\n")
			authRequired++
			db.Exec("UPDATE proxies SET status='auth_required', last_check_time=NOW() WHERE ip=? AND port=?", p.IP, p.Port)
		default:
			fmt.Printf("❌ 不可用 (%s)\n", result)
			unavailable++
			db.Exec("UPDATE proxies SET status='unavailable', last_check_time=NOW() WHERE ip=? AND port=?", p.IP, p.Port)
		}
	}

	fmt.Printf("\n=== 测试结果 ===\n")
	fmt.Printf("可用代理: %d\n", available)
	fmt.Printf("需要认证: %d\n", authRequired)
	fmt.Printf("不可用: %d\n", unavailable)
	fmt.Printf("总计: %d\n", available+authRequired+unavailable)
}

func testProxy(ip string, port int) string {
	address := fmt.Sprintf("%s:%d", ip, port)

	// 建立TCP连接
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return "连接失败"
	}
	defer conn.Close()

	// 设置超时
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// 发送CONNECT请求
	request := "CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n"
	_, err = conn.Write([]byte(request))
	if err != nil {
		return "发送请求失败"
	}

	// 读取响应
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return "无响应"
	}

	response := string(buffer[:n])
	responseLower := strings.ToLower(response)

	// 检查响应
	if !strings.HasPrefix(response, "HTTP/") {
		return "非HTTP响应"
	}

	// 407 - 需要认证
	if strings.Contains(response, "407") {
		return "auth_required"
	}

	// 200 - 可用
	if strings.Contains(response, " 200 ") {
		// 检查是否是真正的代理响应
		if strings.Contains(responseLower, "connection established") ||
			strings.Contains(responseLower, "tunnel") {
			return "available"
		}
		// 短响应也可能是代理
		if len(response) < 200 {
			return "available"
		}
		return "疑似Web服务器"
	}

	// 403/405 - 拒绝CONNECT但可能是代理
	if strings.Contains(response, "403") || strings.Contains(response, "405") {
		return "拒绝CONNECT"
	}

	return "其他响应: " + strings.Split(response, "\n")[0]
}
