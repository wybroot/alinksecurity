package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"alinksec/pkg/cfw"
	"alinksec/pkg/logger"
)

func main() {
	agentID := flag.String("id", "agent-cfw-01", "Cloud Firewall agent identifier")
	hubAddr := flag.String("hub", "127.0.0.1:9090", "AlinkSec Hub gRPC address")
	standalone := flag.Bool("standalone", false, "Run in standalone mode")
	exportNft := flag.Bool("export-nft", false, "Export current rules to Linux nftables format and exit")
	evalSrc := flag.String("eval-src", "", "Evaluate packet src IP (e.g. 10.0.1.10)")
	evalDst := flag.String("eval-dst", "", "Evaluate packet dst IP (e.g. 10.0.3.50)")
	evalPort := flag.Int("eval-port", 3306, "Evaluate packet dst port")
	evalProto := flag.String("eval-proto", "TCP", "Evaluate packet protocol")

	flag.Parse()

	logger.InitGlobalLogger(logger.Config{
		Level:  "info",
		Format: "json",
	}, nil)

	hostname, _ := os.Hostname()

	cfg := &cfw.AgentConfig{
		AgentID:      *agentID,
		Hostname:     hostname,
		HubAddr:      *hubAddr,
		HeartbeatSec: 5 * time.Second,
		Standalone:   *standalone,
	}

	agent := cfw.NewCFWAgent(cfg)

	// 导出 nftables
	if *exportNft {
		fmt.Println(agent.GetEngine().ExportNftables())
		return
	}

	// 命令行单包评估测试
	if *evalSrc != "" && *evalDst != "" {
		res := agent.InspectPacket(cfw.PacketContext{
			SrcIP:    *evalSrc,
			DstIP:    *evalDst,
			DstPort:  *evalPort,
			Protocol: *evalProto,
		})
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		return
	}

	if err := agent.Start(); err != nil {
		logger.Error("Failed to start CFW agent", "err", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	agent.Stop()
}
