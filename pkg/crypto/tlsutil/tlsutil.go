package tlsutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// CertPair 保存证书和私钥 PEM
type CertPair struct {
	CertPEM []byte
	KeyPEM  []byte
}

// GenerateCA 生成自签根 CA 证书
func GenerateCA(commonName string, validDays int) (*CertPair, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA private key failed: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA serial number failed: %w", err)
	}

	notBefore := time.Now().Add(-10 * time.Minute)
	notAfter := notBefore.Add(time.Duration(validDays) * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{"AlinkSec Security"},
			Country:       []string{"CN"},
			Province:      []string{"Beijing"},
			Locality:      []string{"Beijing"},
			CommonName:    commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA certificate failed: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal CA private key failed: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	return &CertPair{CertPEM: certPEM, KeyPEM: keyPEM}, priv, nil
}

// GenerateSignedCert 使用 CA 签发服务端或客户端证书
func GenerateSignedCert(caPair *CertPair, caPriv *ecdsa.PrivateKey, commonName string, isServer bool, validDays int, hosts []string) (*CertPair, error) {
	caCertBlock, _ := pem.Decode(caPair.CertPEM)
	if caCertBlock == nil {
		return nil, fmt.Errorf("decode CA cert failed")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert failed: %w", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key failed: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number failed: %w", err)
	}

	notBefore := time.Now().Add(-10 * time.Minute)
	notAfter := notBefore.Add(time.Duration(validDays) * 24 * time.Hour)

	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if isServer {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"AlinkSec Modular MLPS3"},
			CommonName:   commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caPriv)
	if err != nil {
		return nil, fmt.Errorf("create signed certificate failed: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private key failed: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	return &CertPair{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// SaveCertPair 保存证书与私钥到指定文件路径
func SaveCertPair(pair *CertPair, certPath, keyPath string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, pair.CertPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pair.KeyPEM, 0600); err != nil {
		return err
	}
	return nil
}

// LoadServerMTLSCredentials 生成 gRPC 服务端 mTLS 凭证（强制双向验证探针客户端证书）
func LoadServerMTLSCredentials(serverCertPEM, serverKeyPEM, caCertPEM []byte) (credentials.TransportCredentials, error) {
	cert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load server key pair failed: %w", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("append CA cert failed")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS13,
	}

	return credentials.NewTLS(tlsConfig), nil
}

// LoadClientMTLSCredentials 生成 gRPC 客户端 mTLS 凭证（携带探针客户端证书并验证服务端）
func LoadClientMTLSCredentials(clientCertPEM, clientKeyPEM, caCertPEM []byte, serverName string) (credentials.TransportCredentials, error) {
	cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client key pair failed: %w", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("append CA cert failed")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}

	return credentials.NewTLS(tlsConfig), nil
}

// DialHub 建立探针到 Hub 的 gRPC 连接 (支持 mTLS 双向认证与平滑回退)
func DialHub(ctx context.Context, hubAddr string, tlsEnabled bool, certPath, keyPath, caPath, serverName string) (*grpc.ClientConn, error) {
	var creds credentials.TransportCredentials
	if tlsEnabled && certPath != "" && keyPath != "" && caPath != "" {
		certPEM, err1 := os.ReadFile(certPath)
		keyPEM, err2 := os.ReadFile(keyPath)
		caPEM, err3 := os.ReadFile(caPath)
		if err1 == nil && err2 == nil && err3 == nil {
			if serverName == "" {
				serverName = "alinksec-hub"
			}
			if c, err := LoadClientMTLSCredentials(certPEM, keyPEM, caPEM, serverName); err == nil {
				creds = c
			}
		}
	}
	if creds == nil {
		creds = insecure.NewCredentials()
	}

	return grpc.DialContext(ctx, hubAddr, grpc.WithTransportCredentials(creds))
}
