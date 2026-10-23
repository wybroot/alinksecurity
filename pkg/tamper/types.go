package tamper

import (
	pb "alinksec/api/proto/v1"
)

// TamperAction 篡改动作分类
type TamperAction string

const (
	ActionModified TamperAction = "TAMPER_MODIFIED" // 文件内容被非法修改
	ActionDeleted  TamperAction = "TAMPER_DELETED"  // 文件被非法删除
	ActionCreated  TamperAction = "TAMPER_CREATED"  // 非法上传新增 WebShell / 木马文件
)

// FileRecord 文件安全基线记录
type FileRecord struct {
	RelPath  string `json:"rel_path"`
	FullPath string `json:"full_path"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Mode     uint32 `json:"mode"`
}

// TamperEvent 篡改事件
type TamperEvent struct {
	EventID     string        `json:"event_id"`
	FilePath    string        `json:"file_path"`
	Action      TamperAction  `json:"action"`
	Level       pb.EventLevel `json:"level"`
	OldHash     string        `json:"old_hash,omitempty"`
	NewHash     string        `json:"new_hash,omitempty"`
	Reverted    bool          `json:"reverted"`
	Description string        `json:"description"`
	Timestamp   int64         `json:"timestamp"`
}

// Config 防篡改配置
type Config struct {
	AgentID         string   `json:"agent_id"`
	WatchDir        string   `json:"watch_dir"`        // 监控的 Web 发布根目录
	BackupDir       string   `json:"backup_dir"`       // 本地隔离可信备份目录
	HubAddr         string   `json:"hub_addr"`         // 安全管理中心 gRPC 地址 (可选)
	ProtectedExts   []string `json:"protected_exts"`   // 重点受保护扩展名 (如 .html, .jsp, .php, .js, .css)
	AutoRevert      bool     `json:"auto_revert"`      // 是否开启毫秒级自愈恢复 (默认 true)
	MaintenanceMode bool     `json:"maintenance_mode"` // 是否处于白名单维护发布模式
}
