# 等保 2.0 三级自研安全产品矩阵工程总览与文档索引

本项目旨在面向中国《网络安全等级保护基本要求》（GB/T 22239-2019，**等保 2.0 三级**），打造一套**组件独立解耦、支持自由选配、专机专用轻量 Agent、顶层统一纳管**的企业级安全运营中枢与组件矩阵。

---

## 📚 核心设计与规约文档索引

为了确保研发团队在开发过程中有章可循、步调一致，项目全套设计规范已全部编制成册并归档在 `doc/` 目录下：

| 序号 | 文档名称 | 对应文件路径 | 核心内容摘要 |
| :---: | :--- | :--- | :--- |
| **01** | **系统技术架构设计方案** | [`MLPS3_Modular_Security_Architecture_Design.md`](./MLPS3_Modular_Security_Architecture_Design.md) | 等保三级全套安全组件清单、GitHub 顶级开源项目对标库（Safeline/Coraza/Elkeid/Vector/ClickHouse/JumpServer/Casdoor 等）、解耦选配运行模型、等保三权分立与双因子机制。 |
| **02** | **统一通信与接口规约** | [`MLPS3_Unified_API_and_Protocol_Specification.md`](./MLPS3_Unified_API_and_Protocol_Specification.md) | 南向 gRPC/mTLS 通信协议 (Protobuf 契约)、统一安全事件数据结构、北向 RESTful API、三权分立接口权限矩阵、NATS 消息总线 Topic 规划、ClickHouse 180天存储表结构与主机端文件系统规约。 |
| **03** | **详细研发演进计划** | [`MLPS3_Development_Plan.md`](./MLPS3_Development_Plan.md) | 16 周敏捷研发推进路线图（Phase 0 到 Phase 4）、每双周 Sprint 任务拆解、各阶段验收里程碑、核心风险防范策略（资源防拖垮、存储防爆盘、合规防否决）。 |

---

## 🛠️ 项目代码工程结构规划 (Monorepo 推荐)

为了便于统一代码审查、依赖管理与跨组件协议同步，建议采用 **Monorepo（单代码仓库）** 模式组织整个工程体系：

```
alinksecurity/
├── doc/                                   # 架构与规划文档目录 (已就绪)
│   ├── README.md                          # 本文档 (项目工程总览)
│   ├── MLPS3_Modular_Security_Architecture_Design.md
│   ├── MLPS3_Unified_API_and_Protocol_Specification.md
│   └── MLPS3_Development_Plan.md
│
├── api/                                   # 统一接口协议定义目录
│   └── proto/                             # Protobuf 源文件定义
│       ├── agent_registration.proto       # Agent 注册与握手协议
│       ├── heartbeat.proto                # 心跳与状态上报协议
│       ├── security_event.proto           # 统一安全事件格式定义
│       └── policy_sync.proto              # 安全策略下发协议
│
├── server/                                # 统一安全管理中心 (Control Plane)
│   ├── cmd/soc-server/                    # 服务端启动入口
│   ├── internal/
│   │   ├── auth/                          # Casdoor SSO 认证与 2FA 模块
│   │   ├── rbac/                          # 三权分立权限拦截器
│   │   ├── grpc/                          # 南向 gRPC 服务实现
│   │   ├── api/                           # 北向 RESTful API 路由与控制器
│   │   ├── eventbus/                      # NATS 消息发布与订阅驱动
│   │   └── storage/                       # ClickHouse / MySQL 持久层
│   └── web/                               # 前端控制台源码 (React / Arco Design)
│
├── agents/                                # 各选配独立 Agent 源码 (各组件独立编译)
│   ├── log-agent/                         # 独立日志审计采集器 (Vector 裁剪包装)
│   ├── edr-agent/                         # 独立主机安全 EDR 探针 (防暴破/反弹Shell)
│   ├── cfw-agent/                         # 独立东西向微隔离探针 (nftables 控制器)
│   ├── dbaudit-agent/                     # 独立数据库审计探针 (eBPF 旁路抓包)
│   └── tamper-agent/                      # 独立网页防篡改探针 (fanotify 内核监听)
│
├── deploy/                                # 部署与运维基础设施
│   ├── docker-compose/                    # 开发与测试环境一键拉起编排
│   │   ├── clickhouse/                    # 日志存储引擎 (含 180天 TTL 配置)
│   │   ├── nats/                          # 消息总线
│   │   └── casdoor/                       # 身份认证中心
│   ├── installer/                         # 主机端一键选配安装脚本模板 (install.sh)
│   └── systemd/                           # 各 Agent 独立的 systemd 资源限制模板
│
└── Makefile                               # 统一构建、代码生成与交叉编译指令集
```

---

## 🎯 各阶段交付里程碑自查表

- [ ] **Phase 0 完成**：完成 gRPC Protobuf 代码生成，打通跨平台自动化编译。
- [ ] **Phase 1 完成**：实现【三权分立+2FA】+【ClickHouse 180天日志审计】，达成等保核心红线 MVP。
- [ ] **Phase 2 完成**：落地【JumpServer 运维堡垒机】+【独立 edr-agent】+【一键选配安装脚本】。
- [ ] **Phase 3 完成**：补齐【雷池/Coraza WAF】+【cfw-agent 微隔离】+【dbaudit-agent 数据库审计】+【网页防篡改】。
- [ ] **Phase 4 完成**：态势大屏汇聚展示，通过《等保 2.0 三级模拟测评》并一键导出合规证据报告。
