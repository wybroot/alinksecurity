package manager

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"alinksec/pkg/auth"
	"alinksec/pkg/crypto"
)

// User 表示后台管理员用户实体
type User struct {
	ID               int        `json:"id"`
	Username         string     `json:"username"`
	PasswordHash     string     `json:"-"`
	Role             auth.Role  `json:"role"`
	TOTPSecret       string     `json:"-"`
	TOTPEnabled      bool       `json:"totp_enabled"`
	Status           string     `json:"status"` // "active", "locked"
	FailedLoginCount int        `json:"failed_login_count"`
	LockedUntil      *time.Time `json:"locked_until,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// UserStore 管理员存储引擎
type UserStore struct {
	mu    sync.RWMutex
	users map[string]*User
	seq   int
}

// NewUserStore 创建并预置三权分立默认管理员账号
func NewUserStore() *UserStore {
	store := &UserStore{
		users: make(map[string]*User),
		seq:   1,
	}

	// 预置系统管理员
	sysHash, _ := crypto.HashPassword("SysAdmin@AlinkSec2026!")
	store.users["sysadmin"] = &User{
		ID:           1,
		Username:     "sysadmin",
		PasswordHash: sysHash,
		Role:         auth.RoleSysAdmin,
		TOTPEnabled:  false,
		Status:       "active",
		CreatedAt:    time.Now(),
	}

	// 预置安全管理员
	secHash, _ := crypto.HashPassword("SecAdmin@AlinkSec2026!")
	store.users["secadmin"] = &User{
		ID:           2,
		Username:     "secadmin",
		PasswordHash: secHash,
		Role:         auth.RoleSecAdmin,
		TOTPEnabled:  false,
		Status:       "active",
		CreatedAt:    time.Now(),
	}

	// 预置审计管理员
	auditHash, _ := crypto.HashPassword("AuditAdmin@AlinkSec2026!")
	store.users["auditadmin"] = &User{
		ID:           3,
		Username:     "auditadmin",
		PasswordHash: auditHash,
		Role:         auth.RoleAuditAdmin,
		TOTPEnabled:  false,
		Status:       "active",
		CreatedAt:    time.Now(),
	}

	store.seq = 4
	return store
}

// GetUser 获取用户信息
func (s *UserStore) GetUser(username string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return nil, false
	}
	cp := *u
	return &cp, true
}

// CreateUser 创建新管理员 (受三权分立严格制约)
func (s *UserStore) CreateUser(creatorRole auth.Role, username, password string, role auth.Role) (*User, error) {
	// 等保 2.0 强制检查：仅系统管理员有权创建账号
	if creatorRole != auth.RoleSysAdmin {
		return nil, errors.New("MLPS3 violation: only sys_admin can create admin accounts")
	}

	// 验证角色互斥
	if err := auth.ValidateRoleSeparation([]auth.Role{role}); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[username]; exists {
		return nil, fmt.Errorf("user %s already exists", username)
	}

	pwdHash, err := crypto.HashPassword(password)
	if err != nil {
		return nil, err
	}

	u := &User{
		ID:           s.seq,
		Username:     username,
		PasswordHash: pwdHash,
		Role:         role,
		TOTPEnabled:  false,
		Status:       "active",
		CreatedAt:    time.Now(),
	}

	s.seq++
	s.users[username] = u

	cp := *u
	return &cp, nil
}

// SetTOTPSecret 暂存 TOTP 绑定密钥
func (s *UserStore) SetTOTPSecret(username, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[username]
	if !ok {
		return errors.New("user not found")
	}
	u.TOTPSecret = secret
	return nil
}

// EnableTOTP 确认启用双因子认证
func (s *UserStore) EnableTOTP(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[username]
	if !ok {
		return errors.New("user not found")
	}
	u.TOTPEnabled = true
	return nil
}

// ListUsers 列出所有管理员 (安全脱敏)
func (s *UserStore) ListUsers() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]User, 0, len(s.users))
	for _, u := range s.users {
		safeCopy := *u
		safeCopy.PasswordHash = ""
		safeCopy.TOTPSecret = ""
		res = append(res, safeCopy)
	}
	return res
}
