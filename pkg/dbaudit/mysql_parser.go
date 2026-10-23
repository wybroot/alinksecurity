package dbaudit

import (
	"bytes"
	"strings"
)

// MySQLCommand 定义 MySQL 通信命令类型
type MySQLCommand byte

const (
	ComSleep       MySQLCommand = 0x00
	ComQuit        MySQLCommand = 0x01
	ComInitDB      MySQLCommand = 0x02
	ComQuery       MySQLCommand = 0x03
	ComFieldList   MySQLCommand = 0x04
	ComPing        MySQLCommand = 0x0e
	ComStmtPrepare MySQLCommand = 0x16
	ComStmtExecute MySQLCommand = 0x17
	ComStmtClose   MySQLCommand = 0x19
)

// MySQLParser 解析 MySQL 客户端与服务端交互报文
type MySQLParser struct{}

// NewMySQLParser 实例化 MySQL 解析器
func NewMySQLParser() *MySQLParser {
	return &MySQLParser{}
}

// ParseClientPacket 解析来自 MySQL 客户端发送的数据包
func (p *MySQLParser) ParseClientPacket(data []byte) (cmd MySQLCommand, query string, dbName string, ok bool) {
	if len(data) < 5 {
		return 0, "", "", false
	}

	// MySQL 数据包头: 3 字节 payload 长度 + 1 字节序列号
	payloadLen := int(uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16)
	if len(data) < 4+payloadLen || payloadLen < 1 {
		// 若未能读取完整帧，仍尝试解析已到达数据
		if len(data) <= 4 {
			return 0, "", "", false
		}
	}

	cmd = MySQLCommand(data[4])
	payload := data[5:]

	switch cmd {
	case ComQuery:
		query = strings.TrimSpace(string(payload))
		return cmd, query, "", true

	case ComInitDB:
		dbName = strings.TrimSpace(string(payload))
		return cmd, "", dbName, true

	case ComStmtPrepare:
		query = strings.TrimSpace(string(payload))
		return cmd, query, "", true

	case ComQuit:
		return cmd, "QUIT", "", true

	case ComPing:
		return cmd, "PING", "", true

	default:
		// 可能是握手响应或其它控制命令
		return cmd, "", "", true
	}
}

// ParseHandshakeResponse 尝试从客户端握手认证包中提取用户名和预选数据库
func (p *MySQLParser) ParseHandshakeResponse(data []byte) (user string, db string, ok bool) {
	if len(data) < 36 {
		return "", "", false
	}
	// Handshake response 序列号通常为 1 (0 为服务端打招呼)
	if data[3] != 1 {
		return "", "", false
	}
	// 偏移 4 字节为包头
	// Client Capability Flags: 4 字节
	// Max Packet Size: 4 字节
	// Charset: 1 字节
	// Reserved: 23 字节
	offset := 4 + 4 + 4 + 1 + 23
	if len(data) <= offset {
		return "", "", false
	}

	// 查找以 null 字节结尾的 username
	nullIdx := bytes.IndexByte(data[offset:], 0x00)
	if nullIdx < 0 {
		return "", "", false
	}

	user = string(data[offset : offset+nullIdx])
	offset += nullIdx + 1

	// 校验后续是否存在 database 字符串（如果有 CLIENT_CONNECT_WITH_DB 标志位）
	if offset < len(data) {
		// 跳过 auth-response (length-encoded 或固长)
		authLen := int(data[offset])
		offset += 1 + authLen
		if offset < len(data) {
			dbNullIdx := bytes.IndexByte(data[offset:], 0x00)
			if dbNullIdx > 0 {
				db = string(data[offset : offset+dbNullIdx])
			}
		}
	}

	return user, db, true
}

// BuildMockQueryPacket 辅助构造 MySQL COM_QUERY 测试网络包
func BuildMockQueryPacket(sql string) []byte {
	sqlBytes := []byte(sql)
	payloadLen := len(sqlBytes) + 1
	packet := make([]byte, 4+payloadLen)

	// Header: 3 bytes len + 1 byte seq
	packet[0] = byte(payloadLen & 0xff)
	packet[1] = byte((payloadLen >> 8) & 0xff)
	packet[2] = byte((payloadLen >> 16) & 0xff)
	packet[3] = 0 // seq

	packet[4] = byte(ComQuery)
	copy(packet[5:], sqlBytes)
	return packet
}
