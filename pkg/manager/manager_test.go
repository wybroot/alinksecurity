package manager

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pb "alinksec/api/proto/v1"
	"alinksec/pkg/auth"
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
