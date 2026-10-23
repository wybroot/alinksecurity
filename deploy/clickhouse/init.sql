CREATE DATABASE IF NOT EXISTS alinksec;

-- 1. 统一安全事件总表 (留存 >= 180天)
CREATE TABLE IF NOT EXISTS alinksec.security_events (
    event_id UUID DEFAULT generateUUIDv4(),
    source_type LowCardinality(String),
    agent_id String,
    host_ip IPv4,
    hostname String,
    event_time DateTime64(3, 'Asia/Shanghai') DEFAULT now64(3),
    level LowCardinality(String),
    category LowCardinality(String),
    rule_id String,
    message String,
    raw_payload String,
    signature String,
    chain_hash FixedString(64)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(event_time)
ORDER BY (event_time, source_type, level, agent_id)
TTL event_time + INTERVAL 180 DAY DELETE;

-- 2. 管理员操作审计日志 (防篡改哈希链，留存 >= 365天)
CREATE TABLE IF NOT EXISTS alinksec.admin_audit_logs (
    log_id UUID DEFAULT generateUUIDv4(),
    admin_user LowCardinality(String),
    role LowCardinality(String),  -- 'sys_admin', 'sec_admin', 'audit_admin'
    client_ip IPv4,
    action String,
    target_resource String,
    request_body String,
    response_code UInt16,
    status LowCardinality(String),
    created_at DateTime64(3, 'Asia/Shanghai') DEFAULT now64(3),
    prev_hash FixedString(64),
    log_hash FixedString(64)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (created_at, role, admin_user)
TTL created_at + INTERVAL 365 DAY DELETE;
