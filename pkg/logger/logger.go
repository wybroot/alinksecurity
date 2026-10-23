package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
)

var defaultLogger *slog.Logger

func init() {
	// 默认初始化一个控制台日志器
	defaultLogger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

// Config 日志配置
type Config struct {
	Level     string `json:"level"`      // "debug", "info", "warn", "error"
	Format    string `json:"format"`     // "json", "text"
	AddSource bool   `json:"add_source"` // 是否记录代码行号
}

// InitGlobalLogger 初始化全局日志器
func InitGlobalLogger(cfg Config, w io.Writer) *slog.Logger {
	if w == nil {
		w = os.Stdout
	}

	var lvl slog.Level
	switch cfg.Level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level:     lvl,
		AddSource: cfg.AddSource,
	}

	var handler slog.Handler
	if cfg.Format == "text" {
		handler = slog.NewTextHandler(w, opts)
	} else {
		handler = slog.NewJSONHandler(w, opts)
	}

	defaultLogger = slog.New(handler)
	slog.SetDefault(defaultLogger)
	return defaultLogger
}

// L 获取当前默认日志器
func L() *slog.Logger {
	return defaultLogger
}

// Debug 快捷包装
func Debug(msg string, args ...any) {
	defaultLogger.Debug(msg, args...)
}

// Info 快捷包装
func Info(msg string, args ...any) {
	defaultLogger.Info(msg, args...)
}

// Warn 快捷包装
func Warn(msg string, args ...any) {
	defaultLogger.Warn(msg, args...)
}

// Error 快捷包装
func Error(msg string, args ...any) {
	defaultLogger.Error(msg, args...)
}

// With 返回带预置属性的子 Logger
func With(args ...any) *slog.Logger {
	return defaultLogger.With(args...)
}

// WithContext 从 context 提取或关联字段
func WithContext(ctx context.Context) *slog.Logger {
	return defaultLogger
}
