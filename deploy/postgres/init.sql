-- PostgreSQL 初始化脚本: 元数据、三权分立用户表、Agent 注册登记表

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

-- 索引
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_type ON agents(agent_type);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
