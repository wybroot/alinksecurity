package gm

import (
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/tjfoc/gmsm/sm2"
)

// SM2KeyPair 国密 SM2 密钥对结构
type SM2KeyPair struct {
	PrivateKey *sm2.PrivateKey
	PublicKey  *sm2.PublicKey
}

// GenerateSM2KeyPair 生成国密 SM2 密钥对
func GenerateSM2KeyPair() (*SM2KeyPair, error) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &SM2KeyPair{
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
	}, nil
}

// SM2Sign 使用 SM2 私钥对数据签名，返回十六进制 DER ASN.1 签名串
func SM2Sign(priv *sm2.PrivateKey, data []byte) (string, error) {
	if priv == nil {
		return "", errors.New("sm2: private key is nil")
	}
	sigBytes, err := priv.Sign(rand.Reader, data, nil)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sigBytes), nil
}

// SM2Verify 使用 SM2 公钥对十六进制签名进行验签
func SM2Verify(pub *sm2.PublicKey, data []byte, sigHex string) bool {
	if pub == nil {
		return false
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return pub.Verify(data, sigBytes)
}
