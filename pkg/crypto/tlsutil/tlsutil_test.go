package tlsutil

import (
	"testing"
)

func TestMTLSCertGenerationAndCredentials(t *testing.T) {
	// 1. 生成 CA
	caPair, caPriv, err := GenerateCA("AlinkSec Root CA", 365)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// 2. 签发 Hub 服务端证书
	serverPair, err := GenerateSignedCert(caPair, caPriv, "alinksec-hub", true, 365, []string{"127.0.0.1", "localhost", "alinksec-hub"})
	if err != nil {
		t.Fatalf("GenerateSignedCert server failed: %v", err)
	}

	// 3. 签发 Agent 客户端证书
	clientPair, err := GenerateSignedCert(caPair, caPriv, "alinksec-agent", false, 365, []string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatalf("GenerateSignedCert client failed: %v", err)
	}

	// 4. 构建 gRPC 服务端 mTLS 凭证
	serverCreds, err := LoadServerMTLSCredentials(serverPair.CertPEM, serverPair.KeyPEM, caPair.CertPEM)
	if err != nil {
		t.Fatalf("LoadServerMTLSCredentials failed: %v", err)
	}
	if serverCreds == nil {
		t.Fatal("serverCreds is nil")
	}

	// 5. 构建 gRPC 客户端 mTLS 凭证
	clientCreds, err := LoadClientMTLSCredentials(clientPair.CertPEM, clientPair.KeyPEM, caPair.CertPEM, "alinksec-hub")
	if err != nil {
		t.Fatalf("LoadClientMTLSCredentials failed: %v", err)
	}
	if clientCreds == nil {
		t.Fatal("clientCreds is nil")
	}
}
