package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pb "alinksec/api/proto/v1"
	"alinksec/pkg/auth"
	"alinksec/pkg/storage"
)

func TestThreeRoleSeparationAndAudit(t *testing.T) {
	jwtSecret := []byte("test-jwt-secret-key-for-manager-test")
	srv := NewHTTPServer(jwtSecret)
	handler := srv.Router()

	// 1. 系统管理员登录并绑定 2FA
	loginBody, _ := json.Marshal(map[string]string{
		"username": "sysadmin",
		"password": "SysAdmin@AlinkSec2026!",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(loginBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("sysadmin initial login failed: code %d, body: %s", w.Code, w.Body.String())
	}

	var loginResp LoginResponse
	_ = json.Unmarshal(w.Body.Bytes(), &loginResp)
	if loginResp.TwoFactorState != "SETUP_REQUIRED" {
		t.Fatalf("expected SETUP_REQUIRED, got %s", loginResp.TwoFactorState)
	}
	tmpToken := loginResp.Token

	// 2. 获取 TOTP 绑定密钥
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp/setup", nil)
	req.Header.Set("Authorization", "Bearer "+tmpToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("totp setup failed: %s", w.Body.String())
	}
	var setupResp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &setupResp)
	secret := setupResp["secret"]

	// 3. 计算 TOTP 验证码并提交激活
	code, _ := auth.GenerateTOTPCode(secret, time.Now())
	verifyBody, _ := json.Marshal(map[string]string{"code": code})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp/verify", bytes.NewBuffer(verifyBody))
	req.Header.Set("Authorization", "Bearer "+tmpToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("totp verify failed: %s", w.Body.String())
	}
	var verifyResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &verifyResp)
	sysAdminFormalToken := verifyResp["token"].(string)

	// 4. 安全管理员 Token 签发 (用于权限互斥测试)
	secAdminToken, _ := auth.IssueToken(jwtSecret, "secadmin", auth.RoleSecAdmin, true, 2*time.Hour)

	// 5. 审计管理员 Token 签发 (用于权限互斥测试)
	auditAdminToken, _ := auth.IssueToken(jwtSecret, "auditadmin", auth.RoleAuditAdmin, true, 2*time.Hour)

	// ==================== 三权分立权限互斥验证 ====================

	// 场景 A: 系统管理员 sys_admin 尝试调阅审计日志 -> 必须被 403 强拦截
	req = httptest.NewRequest(http.MethodGet, "/api/v1/audit/logs", nil)
	req.Header.Set("Authorization", "Bearer "+sysAdminFormalToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for sys_admin reading audit logs, got %d", w.Code)
	}

	// 场景 B: 系统管理员 sys_admin 尝试配置安全策略 -> 必须被 403 强拦截
	policyBody, _ := json.Marshal(SecurityPolicyPackage{
		AgentType: "EDR",
		Version:   "v2.0.0",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewBuffer(policyBody))
	req.Header.Set("Authorization", "Bearer "+sysAdminFormalToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for sys_admin writing policy, got %d", w.Code)
	}

	// 场景 C: 安全管理员 sec_admin 配置安全策略 -> 正常 200 成功
	policyUpdate, _ := json.Marshal(SecurityPolicyPackage{
		AgentType: "EDR",
		Version:   "v1.0.1",
		FileRules: []*pb.FileRule{
			{RuleId: "r-99", PathPattern: "/var/log/**", IsProtected: true},
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewBuffer(policyUpdate))
	req.Header.Set("Authorization", "Bearer "+secAdminToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("sec_admin update policy failed: %d, %s", w.Code, w.Body.String())
	}

	// 场景 D: 安全管理员 sec_admin 尝试新增管理员用户 -> 必须被 403 强拦截
	userBody, _ := json.Marshal(CreateUserRequest{
		Username: "hacker",
		Password: "Password123!",
		Role:     auth.RoleSysAdmin,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/system/users", bytes.NewBuffer(userBody))
	req.Header.Set("Authorization", "Bearer "+secAdminToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for sec_admin creating user, got %d", w.Code)
	}

	// 场景 E: 审计管理员 audit_admin 调阅审计日志及防篡改核验 -> 正常 200 成功
	req = httptest.NewRequest(http.MethodGet, "/api/v1/audit/logs", nil)
	req.Header.Set("Authorization", "Bearer "+auditAdminToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("audit_admin read logs failed: %d, %s", w.Code, w.Body.String())
	}
	var logs []AdminAuditRecord
	_ = json.Unmarshal(w.Body.Bytes(), &logs)
	if len(logs) == 0 {
		t.Fatal("expected non-empty audit logs")
	}

	// 场景 F: 审计管理员核验审计链区块链式哈希防篡改完整性
	req = httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil)
	req.Header.Set("Authorization", "Bearer "+auditAdminToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("audit verify failed: %d, %s", w.Code, w.Body.String())
	}
	var verifyChainResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &verifyChainResp)
	if verifyChainResp["chain_valid"] != true {
		t.Fatalf("audit hash chain is corrupted! resp: %+v", verifyChainResp)
	}

	// 场景 G: 审计管理员导出等保合规核查报告
	req = httptest.NewRequest(http.MethodGet, "/api/v1/compliance/report", nil)
	req.Header.Set("Authorization", "Bearer "+auditAdminToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("compliance report failed: %d, %s", w.Code, w.Body.String())
	}

	// 场景 H: 态势感知大屏与报告导出验证
	req = httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("dashboard overview failed: %d, %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/compliance/export.md", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte("GB/T 22239-2019")) {
		t.Fatalf("export markdown failed: %d, %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("dashboard html failed: %d", w.Code)
	}
}

func TestBastionAndSimulationEndpoints(t *testing.T) {
	server := NewHTTPServer([]byte("secret-key-for-test-32bytes-1234"))
	handler := server.Router()

	// 1. 获取 4A 会话列表
	req := httptest.NewRequest(http.MethodGet, "/api/v1/bastion/sessions", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("failed to get bastion sessions: %d", w.Code)
	}

	// 2. 测试高危指令评估 (rm -rf /)
	evalPayload := []byte(`{"command":"rm -rf /"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/bastion/evaluate", bytes.NewBuffer(evalPayload))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("failed to evaluate bastion command: %d", w.Code)
	}
	var evalResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &evalResp)
	if evalResp["allowed"] != false {
		t.Fatalf("expected rm -rf / to be disallowed, got allowed")
	}

	// 3. 测试一键全栈红蓝对抗演练
	req = httptest.NewRequest(http.MethodPost, "/api/v1/simulate/run", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("failed to run simulation: %d", w.Code)
	}
	var simReport map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &simReport)
	if simReport["overall_verdict"] != "PASS" {
		t.Fatalf("expected simulation verdict PASS, got %v", simReport["overall_verdict"])
	}
	if simReport["successful_blocks"] != float64(8) {
		t.Fatalf("expected 8 successful blocks, got %v", simReport["successful_blocks"])
	}
}

func TestBackupAndGMEndpoints(t *testing.T) {
	server := NewHTTPServer([]byte("secret-key-for-test-32bytes-1234"))
	handler := server.Router()

	// 1. 获取灾备快照列表
	req := httptest.NewRequest(http.MethodGet, "/api/v1/backup/snapshots", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("failed to list backup snapshots: %d", w.Code)
	}

	// 2. 创建异地备份快照
	body := []byte(`{"location":"OFFSITE_DISASTER_RECOVERY"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/backup/create", bytes.NewBuffer(body))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("failed to create backup snapshot: %d", w.Code)
	}
	var snapResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &snapResp)
	snapID, ok := snapResp["snapshot_id"].(string)
	if !ok || snapID == "" {
		t.Fatalf("missing snapshot_id in response")
	}

	// 3. 容灾恢复演练
	restoreBody := []byte(fmt.Sprintf(`{"snapshot_id":"%s"}`, snapID))
	req = httptest.NewRequest(http.MethodPost, "/api/v1/backup/restore", bytes.NewBuffer(restoreBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("failed to restore backup snapshot: %d", w.Code)
	}
	var restoreResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &restoreResp)
	if restoreResp["compliance_status"] != "PASS" {
		t.Fatalf("expected restore status PASS, got %v", restoreResp["compliance_status"])
	}

	// 4. 国密密评合规状态
	req = httptest.NewRequest(http.MethodGet, "/api/v1/gm/status", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("failed to get GM status: %d", w.Code)
	}
	var gmResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &gmResp)
	if gmResp["compliance_level"] != "LEVEL_3_COMPLIANT" {
		t.Fatalf("expected LEVEL_3_COMPLIANT, got %v", gmResp["compliance_level"])
	}
}

func TestSOAREndpoints(t *testing.T) {
	jwtSecret := []byte("test-jwt-secret-key-32-bytes-long!")
	server := NewHTTPServer(jwtSecret)
	handler := server.Router()

	// 1. 获取事件与攻击链
	req := httptest.NewRequest(http.MethodGet, "/api/v1/soar/incidents", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 2. 获取封禁池
	req = httptest.NewRequest(http.MethodGet, "/api/v1/soar/blocked-ips", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 3. 获取剧本
	req = httptest.NewRequest(http.MethodGet, "/api/v1/soar/playbooks", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 4. 触发演练
	drillBody := []byte(`{"drill_ip":"198.51.100.99"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/soar/trigger-drill", bytes.NewBuffer(drillBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 5. 解封
	unblockBody := []byte(`{"ip":"198.51.100.99","admin_user":"sec_admin"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/soar/unblock", bytes.NewBuffer(unblockBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAssetAndAlertEndpoints(t *testing.T) {
	jwtSecret := []byte("test-jwt-secret-key-32-bytes-long!")
	server := NewHTTPServer(jwtSecret)
	handler := server.Router()

	// 1. 获取资产列表
	req := httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 2. 资产定级变更
	classifyBody := []byte(`{"id":"AST-001","zone":"DMZ","criticality":"TIER_1_CRITICAL","owner":"核心网络组"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/assets/classify", bytes.NewBuffer(classifyBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 3. 获取资产统计
	req = httptest.NewRequest(http.MethodGet, "/api/v1/assets/stats", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 4. 获取告警聚合与降噪统计
	req = httptest.NewRequest(http.MethodGet, "/api/v1/alerts/aggregations", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 5. 获取通知渠道
	req = httptest.NewRequest(http.MethodGet, "/api/v1/alerts/channels", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 6. 模拟告警测试通道
	testChanBody := []byte(`{"channel_id":"CH-DINGTALK"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/alerts/channels/test", bytes.NewBuffer(testChanBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 7. 模拟 50 次密集攻击并验证滑动窗口降噪
	simBody := []byte(`{}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/alerts/trigger-simulation", bytes.NewBuffer(simBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var simResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &simResp)
	if simResp["success"] != true {
		t.Fatalf("expected simulation success")
	}
}

func TestProductionManagerDatabaseOverlay(t *testing.T) {
	jwtSecret := []byte("test-jwt-secret-key-for-manager-test")
	memStore := storage.NewMemoryStorage()

	// 向持久化数据库中写入一个真实探针
	now := time.Now()
	err := memStore.SaveAgent(context.Background(), &storage.AgentRecord{
		AgentID:           "waf-node-prod-01",
		AgentType:         pb.AgentType_AGENT_WAF,
		AgentTypeStr:      "AGENT_WAF",
		Version:           "v1.5.0",
		Hostname:          "prod-edge-waf",
		IP:                "192.168.10.25",
		Status:            "online",
		CPUUsage:          12.5,
		MemoryUsedBytes:   256 * 1024 * 1024,
		ActiveRulesCount:  68,
		LastHeartbeatTime: now,
		CreatedAt:         now,
		UpdatedAt:         now,
	})
	if err != nil {
		t.Fatalf("failed to save agent: %v", err)
	}

	srv := NewProductionHTTPServer(jwtSecret, memStore, nil)
	handler := srv.Router()

	// 验证 GET /api/v1/system/agents 直接从真实数据库返回探针列表
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/agents", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var agents []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &agents); err != nil {
		t.Fatalf("unmarshal agents failed: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("expected 1 real agent from db, got %d", len(agents))
	}
	if agents[0]["agent_id"] != "waf-node-prod-01" {
		t.Fatalf("expected agent_id 'waf-node-prod-01', got %v", agents[0]["agent_id"])
	}

	// 验证 GET /api/v1/dashboard/overview 正确统计真实数据库探针总数与在线数
	req = httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var overview map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &overview); err != nil {
		t.Fatalf("unmarshal overview failed: %v", err)
	}
	if int(overview["total_agents"].(float64)) != 1 {
		t.Fatalf("expected total_agents 1, got %v", overview["total_agents"])
	}
	if int(overview["online_agents"].(float64)) != 1 {
		t.Fatalf("expected online_agents 1, got %v", overview["online_agents"])
	}
}
