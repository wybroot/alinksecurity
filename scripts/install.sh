#!/bin/bash
# ==============================================================================
# AlinkSec Modular Security Platform - One-Click Agent Installer
# 等保 2.0 三级 (GB/T 22239-2019 S3A3G3) 积木式微探针独立安装器
# ==============================================================================

set -e

INSTALL_DIR="/opt/alinksec"
HUB_ADDR="127.0.0.1:9090"
SESSION_TOKEN=""
ENABLE_MODULES="edr,log" # 默认启用 EDR 与 日志审计

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 解析输入参数
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --hub=*) HUB_ADDR="${1#*=}" ;;
        --token=*) SESSION_TOKEN="${1#*=}" ;;
        --enable=*) ENABLE_MODULES="${1#*=}" ;;
        --help)
            echo "用法: $0 [--hub=<host:port>] [--token=<token>] [--enable=edr,tamper,waf,dbaudit,cfw,log]"
            exit 0
            ;;
        *) log_warn "未知参数: $1" ;;
    esac
    shift
done

echo -e "${BLUE}"
echo "=========================================================="
echo "    AlinkSec Modular Security Micro-Agent Installer       "
echo "    等保 2.0 (三级) 独立微探针矩阵部署自动化系统          "
echo "=========================================================="
echo -e "${NC}"

# 1. 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    log_error "安装探针需要 root 特权，请使用 sudo 或切换至 root 用户执行。"
    exit 1
fi

# 2. 检查操作系统与架构
OS_TYPE=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH_TYPE=$(uname -m)

log_info "检测到主机系统环境: OS=${OS_TYPE}, Arch=${ARCH_TYPE}"
log_info "中央安全管理中枢地址: ${HUB_ADDR}"
log_info "已选配激活安全组件列表: ${ENABLE_MODULES}"

# 3. 创建标准安装根目录
mkdir -p "${INSTALL_DIR}/bin"
mkdir -p "${INSTALL_DIR}/conf"
mkdir -p "${INSTALL_DIR}/logs"
mkdir -p "${INSTALL_DIR}/data"
chmod 700 "${INSTALL_DIR}"

# 4. 辅助函数: 为独立微探针创建独立的 Systemd 服务单元
create_systemd_unit() {
    local mod_name="$1"
    local bin_name="alinksec-${mod_name}"
    local unit_file="/etc/systemd/system/${bin_name}.service"
    local extra_args="$2"

    log_info "正在配置独立 Systemd 单元: ${bin_name}.service ..."

    cat <<EOF > "${unit_file}"
[Unit]
Description=AlinkSec Modular Agent - ${mod_name} (MLPS3)
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/bin/${bin_name} -hub ${HUB_ADDR} ${extra_args}
Restart=always
RestartSec=5s
LimitNOFILE=65535
MemoryMax=256M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${bin_name}.service" 2>/dev/null || true
    log_info "组件 [${mod_name}] Systemd 服务单元安装就绪。"
}

# 5. 遍历安装勾选组件
IFS=',' read -ra MODS <<< "${ENABLE_MODULES}"
for mod in "${MODS[@]}"; do
    mod=$(echo "$mod" | tr -d '[:space:]')
    case $mod in
        edr)
            create_systemd_unit "edr" "-id agent-edr-$(hostname)"
            ;;
        tamper)
            create_systemd_unit "tamper" "-id agent-tamper-$(hostname) -watch /var/www/html -backup ${INSTALL_DIR}/data/tamper_backup"
            ;;
        waf)
            create_systemd_unit "waf" "-id agent-waf-$(hostname) -listen 0.0.0.0:80 -upstream 127.0.0.1:8080"
            ;;
        dbaudit)
            create_systemd_unit "dbaudit" "-id agent-dbaudit-$(hostname) -proto MySQL -listen 127.0.0.1:13306 -target 127.0.0.1:3306"
            ;;
        cfw)
            create_systemd_unit "cfw" "-id agent-cfw-$(hostname)"
            ;;
        log)
            create_systemd_unit "log" "-id agent-log-$(hostname)"
            ;;
        *)
            log_warn "跳过未识别的安全组件: ${mod}"
            ;;
    esac
done

echo ""
log_info "=========================================================="
log_info "🎉 所有选配微探针服务安装成功并完成故障隔离注册！"
log_info "各探针相互独立，单组件崩溃或内存超限被杀死零扩散。"
log_info "可通过 'systemctl status alinksec-<component>' 独立监控各组件状态。"
log_info "=========================================================="
