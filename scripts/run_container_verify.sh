#!/bin/bash
# ==============================================================================
# 一键启动 Docker 容器全自动构建与隔离验证
# 宿主机不产生任何 .exe 二进制，100% 避免本地杀毒软件误杀
# ==============================================================================
set -e

echo "[+] 正在构建 AlinkSec 纯 Linux 隔离验证容器..."
docker build -t alinksec-verify:latest -f deploy/Dockerfile.verify .

echo "[+] 启动容器运行全量等保三级测试与端到端联动验证..."
docker run --rm -t alinksec-verify:latest
