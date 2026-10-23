# ==============================================================================
# AlinkSec - 态势感知与等保三级控制中心 一键容器化演示启动脚本 (Windows PowerShell)
# ==============================================================================

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "    启动 AlinkSec 等保 2.0 (三级) 模块化态势感知一键演示环境      " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location "$ScriptDir\..\deploy\docker-compose"

docker compose -f docker-compose.demo.yml up -d --build

Write-Host "`n✓ 演示服务已在隔离容器内全量启动成功！" -ForegroundColor Green
Write-Host "  -> 态势感知大屏与管理控制台: http://localhost:8080/" -ForegroundColor Cyan
Write-Host "  -> 等保 2.0 三级自检报告:   http://localhost:8080/api/v1/compliance/export.md" -ForegroundColor Cyan
Write-Host "  -> 南向 gRPC 接入中枢:      localhost:50051" -ForegroundColor Cyan
