package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	pb "alinksec/api/proto/v1"
	"alinksec/pkg/logger"

	_ "github.com/lib/pq"
)

// PostgresEngine 基于 PostgreSQL 的生产持久化存储实现
type PostgresEngine struct {
	db *sql.DB
}

// NewPostgresEngine 初始化 PostgreSQL 存储连接池并执行数据库迁移
func NewPostgresEngine(dsn string) (*PostgresEngine, error) {
	return NewPostgresStorage(dsn)
}

// NewPostgresStorage 初始化 PostgreSQL 存储实现
func NewPostgresStorage(dsn string) (*PostgresEngine, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres connection: %w", err)
	}

	// 生产连接池参数配置
	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(10 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping postgres: %w", err)
	}

	engine := &PostgresEngine{db: db}
	if err := engine.autoMigrate(ctx); err != nil {
		return nil, fmt.Errorf("failed to execute postgres schema auto-migration: %w", err)
	}

	logger.Info("PostgreSQL production storage engine initialized successfully")
	return engine, nil
}

func (p *PostgresEngine) autoMigrate(ctx context.Context) error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(64) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		role VARCHAR(32) NOT NULL CHECK (role IN ('sys_admin', 'sec_admin', 'audit_admin')),
		totp_secret VARCHAR(64),
		totp_enabled BOOLEAN DEFAULT FALSE,
		status VARCHAR(16) DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'locked')),
		failed_login_count INT DEFAULT 0,
		locked_until TIMESTAMP WITH TIME ZONE,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS agents (
		agent_id VARCHAR(64) PRIMARY KEY,
		agent_type VARCHAR(32) NOT NULL,
		version VARCHAR(32) NOT NULL,
		hostname VARCHAR(128) NOT NULL,
		ip VARCHAR(45) NOT NULL,
		mac VARCHAR(32),
		os VARCHAR(64),
		arch VARCHAR(32),
		session_token VARCHAR(64),
		status VARCHAR(16) DEFAULT 'online' CHECK (status IN ('online', 'offline', 'revoked')),
		last_heartbeat_at TIMESTAMP WITH TIME ZONE,
		cpu_usage REAL DEFAULT 0,
		mem_used_bytes BIGINT DEFAULT 0,
		disk_used_bytes BIGINT DEFAULT 0,
		active_rules INT DEFAULT 0,
		policy_ver VARCHAR(32) DEFAULT '',
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS policies (
		id SERIAL PRIMARY KEY,
		policy_id VARCHAR(64) UNIQUE NOT NULL,
		version VARCHAR(32) NOT NULL,
		agent_type VARCHAR(32) NOT NULL,
		content JSONB NOT NULL,
		signature VARCHAR(128),
		created_by VARCHAR(64) NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
	CREATE INDEX IF NOT EXISTS idx_agents_type ON agents(agent_type);
	CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
	`
	_, err := p.db.ExecContext(ctx, schema)
	return err
}

func (p *PostgresEngine) SaveAgent(ctx context.Context, agent *AgentRecord) error {
	query := `
	INSERT INTO agents (
		agent_id, agent_type, version, hostname, ip, mac, os, arch, session_token, status,
		last_heartbeat_at, cpu_usage, mem_used_bytes, disk_used_bytes, active_rules, policy_ver, updated_at
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
		$11, $12, $13, $14, $15, $16, CURRENT_TIMESTAMP
	)
	ON CONFLICT (agent_id) DO UPDATE SET
		agent_type = EXCLUDED.agent_type,
		version = EXCLUDED.version,
		hostname = EXCLUDED.hostname,
		ip = EXCLUDED.ip,
		session_token = EXCLUDED.session_token,
		status = EXCLUDED.status,
		last_heartbeat_at = EXCLUDED.last_heartbeat_at,
		updated_at = CURRENT_TIMESTAMP;
	`
	_, err := p.db.ExecContext(ctx, query,
		agent.AgentID, agent.AgentTypeStr, agent.Version, agent.Hostname, agent.IP, agent.MAC, agent.OS, agent.Arch,
		agent.SessionToken, agent.Status, agent.LastHeartbeatTime, agent.CPUUsage, agent.MemoryUsedBytes,
		agent.DiskUsedBytes, agent.ActiveRulesCount, agent.CurrentPolicyVer,
	)
	return err
}

func (p *PostgresEngine) UpdateAgentHeartbeat(ctx context.Context, agentID string, cpu float32, mem, disk int64, rules int32, policyVer string) error {
	query := `
	UPDATE agents SET
		last_heartbeat_at = CURRENT_TIMESTAMP,
		cpu_usage = $2,
		mem_used_bytes = $3,
		disk_used_bytes = $4,
		active_rules = $5,
		policy_ver = $6,
		status = 'online',
		updated_at = CURRENT_TIMESTAMP
	WHERE agent_id = $1;
	`
	_, err := p.db.ExecContext(ctx, query, agentID, cpu, mem, disk, rules, policyVer)
	return err
}

func (p *PostgresEngine) GetAgent(ctx context.Context, agentID string) (*AgentRecord, error) {
	query := `
	SELECT agent_id, agent_type, version, hostname, ip, COALESCE(mac,''), COALESCE(os,''), COALESCE(arch,''),
	       COALESCE(session_token,''), status, COALESCE(last_heartbeat_at, CURRENT_TIMESTAMP),
	       cpu_usage, mem_used_bytes, disk_used_bytes, active_rules, COALESCE(policy_ver,''), created_at, updated_at
	FROM agents WHERE agent_id = $1;
	`
	row := p.db.QueryRowContext(ctx, query, agentID)
	var a AgentRecord
	err := row.Scan(
		&a.AgentID, &a.AgentTypeStr, &a.Version, &a.Hostname, &a.IP, &a.MAC, &a.OS, &a.Arch,
		&a.SessionToken, &a.Status, &a.LastHeartbeatTime,
		&a.CPUUsage, &a.MemoryUsedBytes, &a.DiskUsedBytes, &a.ActiveRulesCount, &a.CurrentPolicyVer,
		&a.CreatedAt, &a.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.AgentType = pb.AgentType(pb.AgentType_value[a.AgentTypeStr])
	return &a, nil
}

func (p *PostgresEngine) ListAgents(ctx context.Context) ([]*AgentRecord, error) {
	query := `
	SELECT agent_id, agent_type, version, hostname, ip, COALESCE(mac,''), COALESCE(os,''), COALESCE(arch,''),
	       COALESCE(session_token,''), status, COALESCE(last_heartbeat_at, CURRENT_TIMESTAMP),
	       cpu_usage, mem_used_bytes, disk_used_bytes, active_rules, COALESCE(policy_ver,''), created_at, updated_at
	FROM agents ORDER BY created_at ASC;
	`
	rows, err := p.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*AgentRecord
	for rows.Next() {
		var a AgentRecord
		if err := rows.Scan(
			&a.AgentID, &a.AgentTypeStr, &a.Version, &a.Hostname, &a.IP, &a.MAC, &a.OS, &a.Arch,
			&a.SessionToken, &a.Status, &a.LastHeartbeatTime,
			&a.CPUUsage, &a.MemoryUsedBytes, &a.DiskUsedBytes, &a.ActiveRulesCount, &a.CurrentPolicyVer,
			&a.CreatedAt, &a.UpdatedAt,
		); err != nil {
			return nil, err
		}
		a.AgentType = pb.AgentType(pb.AgentType_value[a.AgentTypeStr])
		list = append(list, &a)
	}
	return list, rows.Err()
}

func (p *PostgresEngine) MarkOfflineAgents(ctx context.Context, timeoutThreshold time.Duration) (int64, error) {
	deadline := time.Now().Add(-timeoutThreshold)
	query := `
	UPDATE agents SET status = 'offline', updated_at = CURRENT_TIMESTAMP
	WHERE status = 'online' AND last_heartbeat_at < $1;
	`
	res, err := p.db.ExecContext(ctx, query, deadline)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (p *PostgresEngine) GetUserByUsername(ctx context.Context, username string) (*UserRecord, error) {
	query := `
	SELECT id, username, password_hash, role, COALESCE(totp_secret,''), totp_enabled, status,
	       failed_login_count, locked_until, created_at, updated_at
	FROM users WHERE username = $1;
	`
	row := p.db.QueryRowContext(ctx, query, username)
	var u UserRecord
	err := row.Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.TOTPSecret, &u.TOTPEnabled, &u.Status,
		&u.FailedLoginCount, &u.LockedUntil, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (p *PostgresEngine) CreateUser(ctx context.Context, user *UserRecord) error {
	query := `
	INSERT INTO users (username, password_hash, role, totp_secret, totp_enabled, status, created_at, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	RETURNING id;
	`
	return p.db.QueryRowContext(ctx, query,
		user.Username, user.PasswordHash, user.Role, user.TOTPSecret, user.TOTPEnabled, user.Status,
	).Scan(&user.ID)
}

func (p *PostgresEngine) UpdateUser(ctx context.Context, user *UserRecord) error {
	query := `
	UPDATE users SET
		password_hash = $2,
		role = $3,
		totp_secret = $4,
		totp_enabled = $5,
		status = $6,
		failed_login_count = $7,
		locked_until = $8,
		updated_at = CURRENT_TIMESTAMP
	WHERE id = $1;
	`
	_, err := p.db.ExecContext(ctx, query,
		user.ID, user.PasswordHash, user.Role, user.TOTPSecret, user.TOTPEnabled, user.Status,
		user.FailedLoginCount, user.LockedUntil,
	)
	return err
}

func (p *PostgresEngine) ListUsers(ctx context.Context) ([]*UserRecord, error) {
	query := `
	SELECT id, username, role, totp_enabled, status, failed_login_count, locked_until, created_at, updated_at
	FROM users ORDER BY id ASC;
	`
	rows, err := p.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*UserRecord
	for rows.Next() {
		var u UserRecord
		if err := rows.Scan(
			&u.ID, &u.Username, &u.Role, &u.TOTPEnabled, &u.Status,
			&u.FailedLoginCount, &u.LockedUntil, &u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, err
		}
		list = append(list, &u)
	}
	return list, rows.Err()
}

func (p *PostgresEngine) SavePolicy(ctx context.Context, policy *PolicyRecord) error {
	query := `
	INSERT INTO policies (policy_id, version, agent_type, content, signature, created_by, created_at)
	VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
	ON CONFLICT (policy_id) DO UPDATE SET
		version = EXCLUDED.version,
		content = EXCLUDED.content,
		signature = EXCLUDED.signature,
		created_by = EXCLUDED.created_by,
		created_at = CURRENT_TIMESTAMP;
	`
	_, err := p.db.ExecContext(ctx, query,
		policy.PolicyID, policy.Version, policy.AgentType, policy.Content, policy.Signature, policy.CreatedBy,
	)
	return err
}

func (p *PostgresEngine) GetPolicy(ctx context.Context, agentType string) (*PolicyRecord, error) {
	query := `
	SELECT id, policy_id, version, agent_type, content, COALESCE(signature,''), created_by, created_at
	FROM policies WHERE agent_type = $1 ORDER BY created_at DESC LIMIT 1;
	`
	row := p.db.QueryRowContext(ctx, query, agentType)
	var pol PolicyRecord
	err := row.Scan(&pol.ID, &pol.PolicyID, &pol.Version, &pol.AgentType, &pol.Content, &pol.Signature, &pol.CreatedBy, &pol.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &pol, nil
}

func (p *PostgresEngine) ListPolicies(ctx context.Context) ([]*PolicyRecord, error) {
	query := `
	SELECT id, policy_id, version, agent_type, content, COALESCE(signature,''), created_by, created_at
	FROM policies ORDER BY agent_type ASC, created_at DESC;
	`
	rows, err := p.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*PolicyRecord
	for rows.Next() {
		var pol PolicyRecord
		if err := rows.Scan(&pol.ID, &pol.PolicyID, &pol.Version, &pol.AgentType, &pol.Content, &pol.Signature, &pol.CreatedBy, &pol.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, &pol)
	}
	return list, rows.Err()
}

func (p *PostgresEngine) Close() error {
	return p.db.Close()
}
