package auth

import (
	"errors"
	"fmt"
)

// Role 等保 2.0 三权分立角色定义
type Role string

const (
	RoleSysAdmin   Role = "sys_admin"   // 系统管理员: 负责系统配置、用户账号维护、基础运行监控
	RoleSecAdmin   Role = "sec_admin"   // 安全管理员: 负责安全策略、微隔离、WAF/EDR规则配置
	RoleAuditAdmin Role = "audit_admin" // 审计管理员: 负责审计日志核查、合规报表、追据取证
)

// Permission 权限标识符
const (
	// 系统管理权限 (sys_admin)
	PermUserManage   = "perm:user:manage"   // 创建/修改/锁定管理员账号
	PermSystemConfig = "perm:system:config" // 基础参数配置
	PermSystemBackup = "perm:system:backup" // 备份恢复操作

	// 安全策略权限 (sec_admin)
	PermPolicyWrite   = "perm:policy:write"   // 新增/修改/发布防御策略
	PermPolicyRead    = "perm:policy:read"    // 查看安全策略
	PermAgentControl  = "perm:agent:control"  // 探针重启/升级/下发
	PermThreatRespond = "perm:threat:respond" // 威胁阻断/处置

	// 审计管理权限 (audit_admin)
	PermAuditRead   = "perm:audit:read"   // 查阅系统及管理员操作审计日志
	PermAuditExport = "perm:audit:export" // 导出审计底稿及哈希防篡改凭证
	PermCompliance  = "perm:compliance"   // 生成等保合规核查报告
)

// rolePermissionsMap 严格的三权分立权限互斥矩阵
var rolePermissionsMap = map[Role]map[string]bool{
	RoleSysAdmin: {
		PermUserManage:   true,
		PermSystemConfig: true,
		PermSystemBackup: true,
	},
	RoleSecAdmin: {
		PermPolicyWrite:   true,
		PermPolicyRead:    true,
		PermAgentControl:  true,
		PermThreatRespond: true,
	},
	RoleAuditAdmin: {
		PermAuditRead:   true,
		PermAuditExport: true,
		PermCompliance:  true,
	},
}

// CheckPermission 检查指定角色是否具备相应操作权限
func CheckPermission(role Role, requiredPerm string) bool {
	perms, ok := rolePermissionsMap[role]
	if !ok {
		return false
	}
	return perms[requiredPerm]
}

// ValidateRoleSeparation 等保2.0强制合规核查：严禁一人兼任多重互斥特权角色
func ValidateRoleSeparation(roles []Role) error {
	if len(roles) == 0 {
		return errors.New("user must be assigned exactly one role")
	}
	if len(roles) > 1 {
		return fmt.Errorf("MLPS3 violation: multiple roles assignment forbidden under Three-Role Separation (got %d roles)", len(roles))
	}

	role := roles[0]
	switch role {
	case RoleSysAdmin, RoleSecAdmin, RoleAuditAdmin:
		return nil
	default:
		return fmt.Errorf("unknown or invalid MLPS3 role: %s", role)
	}
}
