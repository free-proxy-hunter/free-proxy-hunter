#!/bin/bash

# Free Proxy Hunter 项目管理脚本
# 用于构建和启动前端、后端和扫描器

set -e

PROJECT_ROOT="/Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter"
API_DIR="$PROJECT_ROOT/free-proxy-hunter-api-server"
WEB_DIR="$PROJECT_ROOT/free-proxy-hunter-webpage"
SCANNER_DIR="$PROJECT_ROOT/free-proxy-scanner"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查 PM2 是否安装
check_pm2() {
    if ! command -v pm2 &> /dev/null; then
        log_error "PM2 未安装，请先安装: npm install -g pm2"
        exit 1
    fi
}

# 构建 API 服务器
build_api() {
    log_info "构建 API 服务器..."
    cd "$API_DIR"

    # 创建日志目录
    mkdir -p logs

    # 检查配置文件
    if [ ! -f "configs/config.yaml" ]; then
        log_warn "API 配置文件不存在，复制示例配置..."
        cp configs/config.example.yaml configs/config.yaml
    fi

    # 编译
    go build -o free-proxy-hunter-api-server cmd/server/main.go

    log_success "API 服务器构建完成"
}

# 构建前端
build_web() {
    log_info "构建前端..."
    cd "$WEB_DIR"

    # 创建日志目录
    mkdir -p logs

    # 检查 node_modules
    if [ ! -d "node_modules" ]; then
        log_info "安装前端依赖..."
        npm install
    fi

    log_success "前端依赖已安装"
}

# 构建扫描器
build_scanner() {
    log_info "构建扫描器..."
    cd "$SCANNER_DIR"

    # 创建日志目录
    mkdir -p logs

    # 检查配置文件
    if [ ! -f "configs/config.yaml" ]; then
        log_warn "扫描器配置文件不存在，复制示例配置..."
        cp configs/config.example.yaml configs/config.yaml
    fi

    # 编译
    go build -o scanner cmd/scanner/main.go

    log_success "扫描器构建完成"
}

# 构建所有
build_all() {
    log_info "开始构建所有组件..."
    build_api
    build_web
    build_scanner
    log_success "所有组件构建完成"
}

# 启动所有服务
start() {
    log_info "启动所有服务..."
    check_pm2
    cd "$PROJECT_ROOT"
    pm2 start ecosystem.config.js
    log_success "服务已启动"
    pm2 status
}

# 停止所有服务
stop() {
    log_info "停止所有服务..."
    check_pm2
    cd "$PROJECT_ROOT"
    pm2 stop ecosystem.config.js
    log_success "服务已停止"
}

# 重启所有服务
restart() {
    log_info "重启所有服务..."
    check_pm2
    cd "$PROJECT_ROOT"
    pm2 restart ecosystem.config.js
    log_success "服务已重启"
}

# 查看状态
status() {
    check_pm2
    pm2 status
}

# 查看日志
logs() {
    check_pm2
    pm2 logs
}

# 监控
monitor() {
    check_pm2
    pm2 monitor
}

# 删除所有服务
delete_all() {
    log_warn "删除所有 PM2 服务..."
    check_pm2
    cd "$PROJECT_ROOT"
    pm2 delete ecosystem.config.js
    log_success "服务已删除"
}

# 保存 PM2 配置
save() {
    check_pm2
    pm2 save
    log_success "PM2 配置已保存"
}

# 设置开机自启
startup() {
    check_pm2
    pm2 startup
    log_success "开机自启已设置"
}

# 显示使用帮助
usage() {
    echo "Free Proxy Hunter 项目管理脚本"
    echo ""
    echo "用法: $0 [命令]"
    echo ""
    echo "命令:"
    echo "  build         构建所有组件 (API服务器、前端、扫描器)"
    echo "  build:api     仅构建 API 服务器"
    echo "  build:web     仅构建前端"
    echo "  build:scanner 仅构建扫描器"
    echo "  start         启动所有服务"
    echo "  stop          停止所有服务"
    echo "  restart       重启所有服务"
    echo "  status        查看服务状态"
    echo "  logs          查看日志"
    echo "  monitor       打开监控面板"
    echo "  delete        删除所有服务"
    echo "  save          保存 PM2 配置"
    echo "  startup       设置开机自启"
    echo ""
    echo "示例:"
    echo "  $0 build      # 首次构建所有组件"
    echo "  $0 start      # 启动所有服务"
    echo "  $0 logs       # 查看实时日志"
}

# 主逻辑
case "${1:-}" in
    build)
        build_all
        ;;
    build:api)
        build_api
        ;;
    build:web)
        build_web
        ;;
    build:scanner)
        build_scanner
        ;;
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    status)
        status
        ;;
    logs)
        logs
        ;;
    monitor)
        monitor
        ;;
    delete)
        delete_all
        ;;
    save)
        save
        ;;
    startup)
        startup
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        usage
        exit 1
        ;;
esac
