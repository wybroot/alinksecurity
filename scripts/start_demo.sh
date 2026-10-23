#!/bin/bash
# ==============================================================================
# AlinkSec - 态势感知与等保三级控制中心 一键容器化演示启动脚本 (Linux/macOS)
# ==============================================================================

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}==================================================================${NC}"
echo -e "${CYAN}    启动 AlinkSec 等保 2.0 (三级) 模块化态势感知一键演示环境      ${NC}"
echo -e "${CYAN}==================================================================${NC}"

cd "$(dirname "$0")/../deploy/docker-compose"

docker compose -f docker-compose.demo.yml up -d --build

echo -e "\n${GREEN}✓ 演示服务已在隔离容器内全量启动成功！${NC}"
echo -e "  -> 态势感知大屏与管理控制台: ${CYAN}http://localhost:18080/${NC}"
echo -e "  -> 等保 2.0 三级自检报告:   ${CYAN}http://localhost:18080/api/v1/compliance/export.md${NC}"
echo -e "  -> 南向 gRPC 接入中枢:      ${CYAN}localhost:50051${NC}"
