package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

func main() {
	// 测试几个已知的公共代理
	testProxies := []struct {
		ip   string
		port int
	}{
		{"8.219.97.248", 80},    // 可能是代理
		{"47.74.152.29", 8888},  // 常见代理端口
		{"47.242.43.70", 3128},  // Squid常用端口
	}

	fmt.Println("=== 测试代理探测 ===")
	for _, p := range testProxies {
		fmt.Printf("\n测试 %s:%d\n", p.ip, p.port)

		// 测试TCP连接
		address := fmt.Sprintf("%s:%d", p.ip, p.port)
		conn, err := net.DialTimeout("tcp", address, 5*time.Second)
		if err != nil {
			fmt.Printf("  TCP连接失败: %v\n", err)
			continue
		}
		fmt.Printf("  ✓ TCP端口开放\n")

		// 测试CONNECT方法
		request := "CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n"
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write([]byte(request))
		if err != nil {
			fmt.Printf("  发送CONNECT失败: %v\n", err)
			conn.Close()
			continue
		}

		// 读取响应
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		conn.Close()

		if err != nil || n == 0 {
			fmt.Printf("  读取响应失败: %v\n", err)
			continue
		}

		response := string(buffer[:n])
		responseLower := strings.ToLower(response)

		fmt.Printf("  响应: %s\n", strings.Split(response, "\n")[0])

		// 检查代理特征
		if strings.Contains(response, " 200 ") {
			if strings.Contains(responseLower, "connection established") {
				fmt.Printf("  ✓✓✓ 确定是代理 (Connection established)\n")
			} else {
				fmt.Printf("  ? 可能是代理 (200 OK 但无Connection established)\n")
			}
		} else if strings.Contains(response, "407") {
			fmt.Printf("  ✓✓✓ 确定是代理 (需要认证)\n")
		} else if strings.Contains(response, "403") || strings.Contains(response, "405") {
			fmt.Printf("  ? 可能是代理 (拒绝CONNECT)\n")
		} else {
			fmt.Printf("  ✗ 不是代理\n")
		}
	}
}
