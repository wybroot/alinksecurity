package auth

import (
	"testing"
	"time"
)

func TestRoleSeparation(t *testing.T) {
	// 1. 合规单角色
	if err := ValidateRoleSeparation([]Role{RoleSysAdmin}); err != nil {
		t.Fatalf("expected valid sys_admin, got err: %v", err)
	}
	if err := ValidateRoleSeparation([]Role{RoleSecAdmin}); err != nil {
		t.Fatalf("expected valid sec_admin, got err: %v", err)
	}
	if err := ValidateRoleSeparation([]Role{RoleAuditAdmin}); err != nil {
		t.Fatalf("expected valid audit_admin, got err: %v", err)
	}

	// 2. 违规多角色兼任 (必须拦截)
	if err := ValidateRoleSeparation([]Role{RoleSysAdmin, RoleSecAdmin}); err == nil {
		t.Fatal("expected error for sys_admin + sec_admin violation")
	}

	// 3. 空角色
	if err := ValidateRoleSeparation([]Role{}); err == nil {
		t.Fatal("expected error for empty roles")
	}
}

func TestCheckPermission(t *testing.T) {
	// 系统管理员有权管理用户，但无权配置安全策略，无权看审计日志
	if !CheckPermission(RoleSysAdmin, PermUserManage) {
		t.Fatal("sys_admin should have PermUserManage")
	}
	if CheckPermission(RoleSysAdmin, PermPolicyWrite) {
		t.Fatal("sys_admin must NOT have PermPolicyWrite")
	}
	if CheckPermission(RoleSysAdmin, PermAuditRead) {
		t.Fatal("sys_admin must NOT have PermAuditRead")
	}

	// 安全管理员有权配策略，但无权管用户，无权看审计日志
	if !CheckPermission(RoleSecAdmin, PermPolicyWrite) {
		t.Fatal("sec_admin should have PermPolicyWrite")
	}
	if CheckPermission(RoleSecAdmin, PermUserManage) {
		t.Fatal("sec_admin must NOT have PermUserManage")
	}
	if CheckPermission(RoleSecAdmin, PermAuditRead) {
		t.Fatal("sec_admin must NOT have PermAuditRead")
	}

	// 审计管理员有权看审计日志，但无权配策略，无权管用户
	if !CheckPermission(RoleAuditAdmin, PermAuditRead) {
		t.Fatal("audit_admin should have PermAuditRead")
	}
	if CheckPermission(RoleAuditAdmin, PermUserManage) {
		t.Fatal("audit_admin must NOT have PermUserManage")
	}
	if CheckPermission(RoleAuditAdmin, PermPolicyWrite) {
		t.Fatal("audit_admin must NOT have PermPolicyWrite")
	}
}

func TestJWTIssueAndVerify(t *testing.T) {
	key := []byte("secret-key-alinksecurity-mlps3-jwt")

	// 1. 签发有效 Token
	token, err := IssueToken(key, "secadmin", RoleSecAdmin, true, 2*time.Hour)
	if err != nil {
		t.Fatalf("failed to issue token: %v", err)
	}

	claims, err := ParseAndVerifyToken(key, token)
	if err != nil {
		t.Fatalf("failed to verify token: %v", err)
	}

	if claims.Subject != "secadmin" || claims.Role != RoleSecAdmin || !claims.TwoFactor {
		t.Fatalf("claims mismatch: %+v", claims)
	}

	// 2. 测试篡改签名检测
	tamperedToken := token + "tamper"
	_, err = ParseAndVerifyToken(key, tamperedToken)
	if err == nil {
		t.Fatal("expected error for tampered signature, got nil")
	}

	// 3. 测试错误密钥校验
	wrongKey := []byte("wrong-key-value-1234567890")
	_, err = ParseAndVerifyToken(wrongKey, token)
	if err != ErrSignatureInvalid {
		t.Fatalf("expected ErrSignatureInvalid, got: %v", err)
	}

	// 4. 测试过期 Token
	expiredToken, err := IssueToken(key, "secadmin", RoleSecAdmin, true, -1*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseAndVerifyToken(key, expiredToken)
	if err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got: %v", err)
	}
}
