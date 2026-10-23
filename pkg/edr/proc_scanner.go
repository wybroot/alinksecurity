package edr

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"alinksec/pkg/logger"
)

// ProcessScanner 生产级主机真实进程轮询审计器
type ProcessScanner struct {
	agent        *Agent
	scanInterval time.Duration
	quarantine   bool // 是否在发现极危进程时主动阻断 (SIGKILL)
}

// NewProcessScanner 创建进程审计器
func NewProcessScanner(agent *Agent, interval time.Duration, quarantine bool) *ProcessScanner {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &ProcessScanner{
		agent:        agent,
		scanInterval: interval,
		quarantine:   quarantine,
	}
}

// Start 启动进程持续审计循环
func (s *ProcessScanner) Start(ctx context.Context) {
	ticker := time.NewTicker(s.scanInterval)
	defer ticker.Stop()

	// 启动时立即执行一次扫描
	s.ScanOnce()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.ScanOnce()
		}
	}
}

// ScanOnce 执行单次全系统进程枚举与特征审查
func (s *ProcessScanner) ScanOnce() []DetectionResult {
	procs := s.EnumerateProcesses()
	var detected []DetectionResult

	for _, proc := range procs {
		res, matched := s.agent.InspectProcess(proc)
		if matched {
			detected = append(detected, res)
			if s.quarantine && proc.PID > 1 {
				s.terminateThreatProcess(proc.PID)
			}
		}
	}

	return detected
}

// EnumerateProcesses 枚举当前操作系统活跃进程
func (s *ProcessScanner) EnumerateProcesses() []ProcessInfo {
	var procs []ProcessInfo

	// 优先尝试读取 Linux /proc 文件系统 (高性能零子进程开销)
	if entries, err := os.ReadDir("/proc"); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pid, err := strconv.Atoi(entry.Name())
			if err != nil || pid <= 0 {
				continue
			}

			cmdlineBytes, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
			if err != nil || len(cmdlineBytes) == 0 {
				continue
			}

			// cmdline 以 null 字节分隔
			cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
			cmdline = strings.TrimSpace(cmdline)

			commBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
			comm := strings.TrimSpace(string(commBytes))
			if comm == "" {
				comm = entry.Name()
			}

			procs = append(procs, ProcessInfo{
				PID:         int32(pid),
				Name:        comm,
				CommandLine: cmdline,
				Username:    "system",
			})
		}
		if len(procs) > 0 {
			return procs
		}
	}

	// 若不在 Linux 或 /proc 无法直接读取，保留当前探针自身进程或测试模拟
	procs = append(procs, ProcessInfo{
		PID:         int32(os.Getpid()),
		Name:        "alinksec-edr",
		CommandLine: strings.Join(os.Args, " "),
		Username:    "current",
	})

	return procs
}

func (s *ProcessScanner) terminateThreatProcess(pid int32) {
	proc, err := os.FindProcess(int(pid))
	if err != nil {
		return
	}
	logger.Warn("EDR Quarantine Active Defense: Terminating threat process", "pid", pid)
	_ = proc.Kill()
}

// ReadFullContent 读取文件全部内容安全包装
func ReadFullContent(r io.Reader) string {
	b, _ := io.ReadAll(r)
	return string(b)
}
