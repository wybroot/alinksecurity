package dbaudit

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// PGMessageType PostgreSQL 客户端消息标识
type PGMessageType byte

const (
	PGMsgSimpleQuery PGMessageType = 'Q' // 简单查询
	PGMsgParse       PGMessageType = 'P' // 预编译解析
	PGMsgBind        PGMessageType = 'B' // 绑定
	PGMsgExecute     PGMessageType = 'E' // 执行
	PGMsgSync        PGMessageType = 'S' // 同步
	PGMsgTerminate   PGMessageType = 'X' // 终止退出
	PGMsgPassword    PGMessageType = 'p' // 密码响应
)

// PGParser 解析 PostgreSQL 交互协议
type PGParser struct{}

// NewPGParser 实例化 PostgreSQL 解析器
func NewPGParser() *PGParser {
	return &PGParser{}
}

// ParseClientPacket 解析 PostgreSQL 客户端请求
func (p *PGParser) ParseClientPacket(data []byte) (msgType PGMessageType, query string, ok bool) {
	if len(data) < 5 {
		return 0, "", false
	}

	msgType = PGMessageType(data[0])
	length := int(binary.BigEndian.Uint32(data[1:5]))
	if len(data) < 1+length {
		// 包长度尚未完全就绪，如果已有内容仍尝试解析
	}

	switch msgType {
	case PGMsgSimpleQuery:
		payload := data[5:]
		if len(payload) > 0 && payload[len(payload)-1] == 0 {
			payload = payload[:len(payload)-1]
		}
		return msgType, strings.TrimSpace(string(payload)), true

	case PGMsgParse:
		// Parse 消息: 'P' + 4 字节长度 + 语句名称(以0结尾) + SQL(以0结尾)
		payload := data[5:]
		nullIdx := bytes.IndexByte(payload, 0x00)
		if nullIdx >= 0 && nullIdx+1 < len(payload) {
			sqlPart := payload[nullIdx+1:]
			sqlEnd := bytes.IndexByte(sqlPart, 0x00)
			if sqlEnd > 0 {
				sqlPart = sqlPart[:sqlEnd]
			}
			return msgType, strings.TrimSpace(string(sqlPart)), true
		}
		return msgType, "", true

	case PGMsgTerminate:
		return msgType, "DISCONNECT", true

	default:
		return msgType, "", true
	}
}

// ParseStartupMessage 解析 PostgreSQL 启动握手消息（提取 user / database）
func (p *PGParser) ParseStartupMessage(data []byte) (user string, db string, ok bool) {
	if len(data) < 8 {
		return "", "", false
	}

	length := int(binary.BigEndian.Uint32(data[0:4]))
	if len(data) < length || length < 8 {
		return "", "", false
	}

	protocol := binary.BigEndian.Uint32(data[4:8])
	// 协议 3.0: 0x00030000
	if protocol != 0x00030000 {
		return "", "", false
	}

	payload := data[8:length]
	params := bytes.Split(payload, []byte{0x00})
	for i := 0; i < len(params)-1; i += 2 {
		k := string(params[i])
		v := string(params[i+1])
		if k == "user" {
			user = v
		} else if k == "database" {
			db = v
		}
	}

	return user, db, true
}

// BuildMockPGQueryPacket 辅助构造 PostgreSQL 简单查询包
func BuildMockPGQueryPacket(sql string) []byte {
	sqlBytes := append([]byte(sql), 0x00)
	length := uint32(len(sqlBytes) + 4)

	buf := make([]byte, 1+4+len(sqlBytes))
	buf[0] = byte(PGMsgSimpleQuery)
	binary.BigEndian.PutUint32(buf[1:5], length)
	copy(buf[5:], sqlBytes)
	return buf
}
