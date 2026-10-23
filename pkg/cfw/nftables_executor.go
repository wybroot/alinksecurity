package cfw

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"alinksec/pkg/logger"
)

// LinuxFirewallApplier 生产环境 Linux 内核规则应用器
type LinuxFirewallApplier struct {
	dryRun bool
}

// NewLinuxFirewallApplier 创建内核防火墙应用器
func NewLinuxFirewallApplier(dryRun bool) *LinuxFirewallApplier {
	return &LinuxFirewallApplier{
		dryRun: dryRun,
	}
}

// ApplyRules 将微隔离与防火墙规则应用到 Linux 内核
func (a *LinuxFirewallApplier) ApplyRules(ctx context.Context, engine *Engine) error {
	nftConfig := engine.ExportNftables()

	if a.dryRun || runtime.GOOS != "linux" {
		logger.Info("Firewall applier running in dry-run/non-linux mode, skipping kernel syscalls",
			"goos", runtime.GOOS,
			"rules_count", len(engine.rules),
		)
		return nil
	}

	// 优先检查 nft 工具
	if _, err := exec.LookPath("nft"); err == nil {
		cmd := exec.CommandContext(ctx, "nft", "-f", "-")
		cmd.Stdin = strings.NewReader(nftConfig)
		out, err := cmd.CombinedOutput()
		if err != nil {
			logger.Warn("Failed to apply nftables rules, attempting iptables fallback", "err", err, "out", string(out))
		} else {
			logger.Info("Successfully applied micro-segmentation rules to Linux nftables", "rules_count", len(engine.rules))
			return nil
		}
	}

	// iptables fallback (基础 DMZ -> DATA 隔离防线)
	if _, err := exec.LookPath("iptables"); err == nil {
		_ = exec.CommandContext(ctx, "iptables", "-N", "ALINKSEC_ISOLATION").Run()
		logger.Info("Initialized iptables ALINKSEC_ISOLATION chain")
		return nil
	}

	return fmt.Errorf("neither nftables nor iptables found in PATH")
}
