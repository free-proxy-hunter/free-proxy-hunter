#!/bin/bash

# Free Proxy Hunter 启动脚本
# 使用 nohup 保持进程运行

PROJECT_DIR="/Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter"
API_DIR="$PROJECT_DIR/free-proxy-hunter-api-server"
WEB_DIR="$PROJECT_DIR/free-proxy-hunter-webpage"
SCANNER_DIR="$PROJECT_DIR/free-proxy-scanner"
LOG_DIR="$PROJECT_DIR/logs"
PID_DIR="$PROJECT_DIR/pids"

# 创建必要的目录
mkdir -p $LOG_DIR $PID_DIR

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 启动 API 服务器
start_api() {
    echo -e "${GREEN}启动 API 服务器...${NC}"
    cd $API_DIR
    nohup ./free-proxy-hunter-api-server > $LOG_DIR/api-server.log 2>&1 &
    echo $! > $PID_DIR/api-server.pid
    echo -e "${GREEN}API 服务器已启动，PID: $!${NC}"
    sleep 2
}

# 启动前端
start_web() {
    echo -e "${GREEN}启动前端开发服务器...${NC}"
    cd $WEB_DIR
    nohup npm run dev > $LOG_DIR/web-server.log 2>&1 &
    echo $! > $PID_DIR/web-server.pid
    echo -e "${GREEN}前端服务器已启动，PID: $!${NC}"
    sleep 3
}

# 启动扫描器
start_scanner() {
    echo -e "${GREEN}启动代理扫描器...${NC}"
    cd $SCANNER_DIR
    nohup ./scanner > $LOG_DIR/scanner.log 2>&1 &
    echo $! > $PID_DIR/scanner.pid
    echo -e "${GREEN}扫描器已启动，PID: $!${NC}"
}

# 停止所有服务
stop_all() {
    echo -e "${YELLOW}停止所有服务...${NC}"

    # 停止 API
    if [ -f $PID_DIR/api-server.pid ]; then
        kill $(cat $PID_DIR/api-server.pid) 2>/dev/null && echo -e "${GREEN}API 服务器已停止${NC}" || echo -e "${RED}API 服务器未运行${NC}"
        rm -f $PID_DIR/api-server.pid
    fi

    # 停止前端
    if [ -f $PID_DIR/web-server.pid ]; then
        kill $(cat $PID_DIR/web-server.pid) 2>/dev/null && echo -e "${GREEN}前端服务器已停止${NC}" || echo -e "${RED}前端服务器未运行${NC}"
        rm -f $PID_DIR/web-server.pid
    fi

    # 停止扫描器
    if [ -f $PID_DIR/scanner.pid ]; then
        kill $(cat $PID_DIR/scanner.pid) 2>/dev/null && echo -e "${GREEN}扫描器已停止${NC}" || echo -e "${RED}扫描器未运行${NC}"
        rm -f $PID_DIR/scanner.pid
    fi

    # 清理残留进程
    pkill -f "free-proxy-hunter-api-server" 2>/dev/null
    pkill -f "vite" 2>/dev/null
    pkill -f "./scanner" 2>/dev/null
}

# 查看状态
status() {
    echo -e "${YELLOW}=== 服务状态 ===${NC}"

    # 检查 API
    if [ -f $PID_DIR/api-server.pid ] && kill -0 $(cat $PID_DIR/api-server.pid) 2>/dev/null; then
        echo -e "${GREEN}✓ API 服务器: 运行中 (PID: $(cat $PID_DIR/api-server.pid))${NC}"
    else
        echo -e "${RED}✗ API 服务器: 未运行${NC}"
    fi

    # 检查前端
    if [ -f $PID_DIR/web-server.pid ] && kill -0 $(cat $PID_DIR/web-server.pid) 2>/dev/null; then
        echo -e "${GREEN}✓ 前端服务器: 运行中 (PID: $(cat $PID_DIR/web-server.pid))${NC}"
    else
        echo -e "${RED}✗ 前端服务器: 未运行${NC}"
    fi

    # 检查扫描器
    if [ -f $PID_DIR/scanner.pid ] && kill -0 $(cat $PID_DIR/scanner.pid) 2>/dev/null; then
        echo -e "${GREEN}✓ 扫描器: 运行中 (PID: $(cat $PID_DIR/scanner.pid))${NC}"
    else
        echo -e "${RED}✗ 扫描器: 未运行${NC}"
    fi

    echo -e "${YELLOW}=== 端口监听 ===${NC}"
    netstat -an 2>/dev/null | grep -E "53361|53362" || echo "未检测到端口监听"
}

# 查看日志
logs() {
    case "$2" in
        api)
            tail -f $LOG_DIR/api-server.log
            ;;
        web)
            tail -f $LOG_DIR/web-server.log
            ;;
        scanner)
            tail -f $LOG_DIR/scanner.log
            ;;
        *)
            echo "Usage: $0 logs [api|web|scanner]"
            ;;
    esac
}

# 自动重启监控
watchdog() {
    while true; do
        # 检查 API
        if [ -f $PID_DIR/api-server.pid ]; then
            if ! kill -0 $(cat $PID_DIR/api-server.pid) 2>/dev/null; then
                echo -e "${YELLOW}[$(date)] API 服务器崩溃，正在重启...${NC}"
                start_api
            fi
        fi

        # 检查前端
        if [ -f $PID_DIR/web-server.pid ]; then
            if ! kill -0 $(cat $PID_DIR/web-server.pid) 2>/dev/null; then
                echo -e "${YELLOW}[$(date)] 前端服务器崩溃，正在重启...${NC}"
                start_web
            fi
        fi

        # 检查扫描器
        if [ -f $PID_DIR/scanner.pid ]; then
            if ! kill -0 $(cat $PID_DIR/scanner.pid) 2>/dev/null; then
                echo -e "${YELLOW}[$(date)] 扫描器崩溃，正在重启...${NC}"
                start_scanner
            fi
        fi

        sleep 10
    done
}

# 启动所有服务
start_all() {
    echo -e "${GREEN}=== 启动 Free Proxy Hunter ===${NC}"
    start_api
    start_web
    start_scanner
    echo -e "${GREEN}=== 所有服务已启动 ===${NC}"
    echo -e "前端: http://localhost:53362"
    echo -e "API:  http://localhost:53361"
    echo ""
    echo -e "${YELLOW}启动看门狗监控...${NC}"
    watchdog &
    echo $! > $PID_DIR/watchdog.pid
}

# 主命令
case "$1" in
    start)
        start_all
        ;;
    stop)
        stop_all
        ;;
    restart)
        stop_all
        sleep 2
        start_all
        ;;
    status)
        status
        ;;
    logs)
        logs "$@"
        ;;
    watchdog)
        watchdog
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs [api|web|scanner]}"
        exit 1
        ;;
esac
