package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"alinksec/pkg/crypto/tlsutil"
	"alinksec/pkg/logger"
)

func main() {
	outDir := flag.String("out", "deploy/certs", "Output directory for certificates")
	flag.Parse()

	logger.InitGlobalLogger(logger.Config{Level: "info", Format: "text"}, os.Stdout)

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		fmt.Printf("Failed to create out dir: %v\n", err)
		os.Exit(1)
	}

	// 1. 生成 CA
	caPair, caPriv, err := tlsutil.GenerateCA("AlinkSec Root CA (MLPS3)", 3650)
	if err != nil {
		fmt.Printf("Generate CA failed: %v\n", err)
		os.Exit(1)
	}
	_ = tlsutil.SaveCertPair(caPair, filepath.Join(*outDir, "ca.crt"), filepath.Join(*outDir, "ca.key"))

	// 2. 签发 Hub 服务端证书
	hubPair, err := tlsutil.GenerateSignedCert(caPair, caPriv, "alinksec-hub", true, 3650, []string{
		"127.0.0.1", "localhost", "alinksec-hub", "hub",
	})
	if err != nil {
		fmt.Printf("Generate Hub cert failed: %v\n", err)
		os.Exit(1)
	}
	_ = tlsutil.SaveCertPair(hubPair, filepath.Join(*outDir, "hub.crt"), filepath.Join(*outDir, "hub.key"))

	// 3. 签发通用 Agent 客户端 mTLS 证书
	agentPair, err := tlsutil.GenerateSignedCert(caPair, caPriv, "alinksec-agent", false, 3650, []string{
		"127.0.0.1", "localhost", "agent",
	})
	if err != nil {
		fmt.Printf("Generate Agent cert failed: %v\n", err)
		os.Exit(1)
	}
	_ = tlsutil.SaveCertPair(agentPair, filepath.Join(*outDir, "agent.crt"), filepath.Join(*outDir, "agent.key"))

	logger.Info("All mTLS certificates successfully generated!",
		"out_dir", *outDir,
		"ca", "ca.crt",
		"server", "hub.crt",
		"client", "agent.crt",
	)
}
