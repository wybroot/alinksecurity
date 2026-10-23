package dbaudit

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

func TestMySQLParser(t *testing.T) {
	parser := NewMySQLParser()

	// 1. COM_QUERY 测试
	queryPacket := BuildMockQueryPacket("SELECT * FROM users WHERE id = 1")
	cmd, query, db, ok := parser.ParseClientPacket(queryPacket)
	if !ok {
		t.Fatalf("expected parse to succeed")
	}
	if cmd != ComQuery {
		t.Errorf("expected ComQuery (0x03), got %v", cmd)
	}
	if query != "SELECT * FROM users WHERE id = 1" {
		t.Errorf("unexpected query text: %s", query)
	}
	if db != "" {
		t.Errorf("unexpected db: %s", db)
	}

	// 2. COM_INIT_DB 测试
	initDbPacket := []byte{0x07, 0x00, 0x00, 0x00, byte(ComInitDB), 't', 'e', 's', 't', 'd', 'b'}
	cmd, _, db, ok = parser.ParseClientPacket(initDbPacket)
	if !ok || cmd != ComInitDB || db != "testdb" {
		t.Errorf("failed to parse ComInitDB: ok=%v, cmd=%v, db=%s", ok, cmd, db)
	}
}

func TestPGParser(t *testing.T) {
	parser := NewPGParser()

	// 1. Simple Query
	queryPacket := BuildMockPGQueryPacket("SELECT count(*) FROM orders")
	msgType, query, ok := parser.ParseClientPacket(queryPacket)
	if !ok {
		t.Fatalf("expected PG parse to succeed")
	}
	if msgType != PGMsgSimpleQuery {
		t.Errorf("expected PGMsgSimpleQuery, got %c", msgType)
	}
	if query != "SELECT count(*) FROM orders" {
		t.Errorf("unexpected query text: %s", query)
	}

	// 2. Startup Message
	buf := new(bytes.Buffer)
	// payload: protocol 3.0 + "user\0admin\0database\0prod\0\0"
	var payload bytes.Buffer
	payload.Write([]byte{0x00, 0x03, 0x00, 0x00}) // v3.0
	payload.WriteString("user\x00admin\x00database\x00prod\x00\x00")
	totalLen := uint32(payload.Len() + 4)

	buf.WriteByte(byte(totalLen >> 24))
	buf.WriteByte(byte(totalLen >> 16))
	buf.WriteByte(byte(totalLen >> 8))
	buf.WriteByte(byte(totalLen))
	buf.Write(payload.Bytes())

	user, db, ok := parser.ParseStartupMessage(buf.Bytes())
	if !ok || user != "admin" || db != "prod" {
		t.Errorf("failed to parse PG startup: ok=%v, user=%s, db=%s", ok, user, db)
	}
}

func TestSQLAnalyzerRiskRules(t *testing.T) {
	analyzer := NewSQLAnalyzer()

	cases := []struct {
		name       string
		sql        string
		wantThreat bool
		wantRisk   RiskLevel
		wantRule   string
	}{
		{
			name:       "Drop Table Destructive",
			sql:        "DROP TABLE customers;",
			wantThreat: true,
			wantRisk:   RiskCritical,
			wantRule:   "DBA-101",
		},
		{
			name:       "Truncate Table Destructive",
			sql:        "TRUNCATE TABLE logs",
			wantThreat: true,
			wantRisk:   RiskCritical,
			wantRule:   "DBA-101",
		},
		{
			name:       "Unconstrained Bulk Delete",
			sql:        "DELETE FROM orders",
			wantThreat: true,
			wantRisk:   RiskCritical,
			wantRule:   "DBA-102",
		},
		{
			name:       "Unconstrained Bulk Update",
			sql:        "UPDATE accounts SET balance = 0",
			wantThreat: true,
			wantRisk:   RiskCritical,
			wantRule:   "DBA-103",
		},
		{
			name:       "Privilege Escalation Grant",
			sql:        "GRANT ALL ON *.* TO 'hacker'@'%'",
			wantThreat: true,
			wantRisk:   RiskHigh,
			wantRule:   "DBA-104",
		},
		{
			name:       "Outfile Data Exfiltration",
			sql:        "SELECT * FROM secret INTO OUTFILE '/tmp/dump.txt'",
			wantThreat: true,
			wantRisk:   RiskHigh,
			wantRule:   "DBA-105",
		},
		{
			name:       "Schema Injection Recon",
			sql:        "SELECT id FROM items WHERE id = 1 UNION SELECT table_name FROM information_schema.tables",
			wantThreat: true,
			wantRisk:   RiskHigh,
			wantRule:   "DBA-106",
		},
		{
			name:       "Normal Select",
			sql:        "SELECT id, name FROM users WHERE id = 42",
			wantThreat: false,
			wantRisk:   RiskInfo,
			wantRule:   "",
		},
		{
			name:       "Normal Update with Where",
			sql:        "UPDATE users SET last_login = NOW() WHERE id = 42",
			wantThreat: false,
			wantRisk:   RiskLow,
			wantRule:   "",
		},
		{
			name:       "Normal Delete with Where",
			sql:        "DELETE FROM sessions WHERE expired_at < NOW()",
			wantThreat: false,
			wantRisk:   RiskLow,
			wantRule:   "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := analyzer.Analyze("10.0.0.5:41234", "10.0.0.10:3306", "app", "shop", tc.sql, ProtoMySQL, 10)
			if rec.IsThreat != tc.wantThreat {
				t.Errorf("IsThreat mismatch for '%s': got %v, want %v", tc.sql, rec.IsThreat, tc.wantThreat)
			}
			if rec.RiskLevel != tc.wantRisk {
				t.Errorf("RiskLevel mismatch for '%s': got %v, want %v", tc.sql, rec.RiskLevel, tc.wantRisk)
			}
			if tc.wantRule != "" && rec.RuleID != tc.wantRule {
				t.Errorf("RuleID mismatch: got %v, want %v", rec.RuleID, tc.wantRule)
			}
		})
	}
}

func TestDBAuditAgentTransparentProxy(t *testing.T) {
	// 1. 模拟目标 DB Server (TCP echo/responder)
	dbListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind mock DB: %v", err)
	}
	defer dbListener.Close()
	dbAddr := dbListener.Addr().String()

	go func() {
		for {
			conn, err := dbListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, rErr := c.Read(buf)
					if rErr != nil {
						return
					}
					// echo back
					_, _ = c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	// 2. 获取可用端口作为代理监听
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get proxy port: %v", err)
	}
	proxyAddr := proxyListener.Addr().String()
	_ = proxyListener.Close() // 释放端口给 agent 使用

	// 3. 启动 DBAuditAgent
	cfg := &AgentConfig{
		AgentID:      "test-dbaudit-agent",
		ListenAddr:   proxyAddr,
		TargetDBAddr: dbAddr,
		Protocol:     ProtoMySQL,
		Standalone:   true,
	}

	agent := NewDBAuditAgent(cfg)

	var recordedMutex sync.Mutex
	var recorded []*AuditRecord

	agent.SetAuditCallback(func(r *AuditRecord) {
		recordedMutex.Lock()
		defer recordedMutex.Unlock()
		recorded = append(recorded, r)
	})

	if err := agent.Start(); err != nil {
		t.Fatalf("failed to start agent: %v", err)
	}
	defer agent.Stop()

	// 等待代理就绪
	time.Sleep(100 * time.Millisecond)

	// 4. 模拟客户端连接代理并发送 MySQL COM_QUERY 数据包
	clientConn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("failed to connect to audit proxy: %v", err)
	}
	defer clientConn.Close()

	// 发送合规 SQL
	safeSQL := BuildMockQueryPacket("SELECT * FROM products WHERE category = 'book'")
	_, _ = clientConn.Write(safeSQL)

	// 发送破坏性 SQL
	threatSQL := BuildMockQueryPacket("DROP TABLE secret_keys")
	_, _ = clientConn.Write(threatSQL)

	// 等待审计记录处理
	time.Sleep(300 * time.Millisecond)

	recordedMutex.Lock()
	defer recordedMutex.Unlock()

	if len(recorded) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(recorded))
	}

	// 验证第二条记录被识别为 CRITICAL 威胁
	var foundThreat bool
	for _, r := range recorded {
		if r.IsThreat && r.RuleID == "DBA-101" {
			foundThreat = true
			if r.RiskLevel != RiskCritical {
				t.Errorf("expected RiskCritical, got %v", r.RiskLevel)
			}
		}
	}

	if !foundThreat {
		t.Errorf("expected DBA-101 threat to be detected")
	}

	queries, threats, _ := agent.GetMetrics()
	if queries < 2 || threats < 1 {
		t.Errorf("unexpected metrics: queries=%d, threats=%d", queries, threats)
	}
}
