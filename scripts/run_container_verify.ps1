# ==============================================================================
# Windows PowerShell 一键启动 Docker 容器全自动构建与隔离验证
# 宿主机不产生任何 .exe 二进制，100% 避免本地杀毒软件误杀
# ==============================================================================

Write-Host "[+] 正在构建 AlinkSec 纯 Linux 隔离验证容器..." -ForegroundColor Cyan
docker build -t alinksec-verify:latest -f deploy/Dockerfile.verify .

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Docker 镜像构建失败" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "[+] 启动容器运行全量等保三级测试与端到端联动验证..." -ForegroundColor Green
docker run --rm -t alinksec-verify:latest
