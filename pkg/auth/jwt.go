package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"alinksec/pkg/crypto"
)

var (
	ErrTokenExpired       = errors.New("token has expired")
	ErrTokenMalformed     = errors.New("malformed token")
	ErrSignatureInvalid   = errors.New("invalid token signature")
	ErrTwoFactorRequired  = errors.New("two-factor authentication required")
)

// Header JWT 头部
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Claims 等保合规管理后台 JWT 载荷
type Claims struct {
	Subject   string `json:"sub"`  // 用户名
	Role      Role   `json:"role"` // 三权分立角色
	TwoFactor bool   `json:"tfa"`  // 是否已通过 2FA/TOTP 双因子认证
	IssuedAt  int64  `json:"iat"`  // 签发时间戳
	ExpiresAt int64  `json:"exp"`  // 过期时间戳 (等保要求会话超时锁定)
	TokenID   string `json:"jti"`  // 唯一会话 ID
}

// IssueToken 签发管理员 JWT 凭据
func IssueToken(signingKey []byte, username string, role Role, twoFactorVerified bool, ttl time.Duration) (string, error) {
	if len(signingKey) == 0 {
		return "", errors.New("signing key cannot be empty")
	}

	header := Header{
		Alg: "HS256",
		Typ: "JWT",
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	jti, err := crypto.GenerateSecureToken(16)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := Claims{
		Subject:   username,
		Role:      role,
		TwoFactor: twoFactorVerified,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
		TokenID:   jti,
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	h64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	p64 := base64.RawURLEncoding.EncodeToString(claimsBytes)
	signedData := h64 + "." + p64

	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(signedData))
	sig := mac.Sum(nil)
	sig64 := base64.RawURLEncoding.EncodeToString(sig)

	return signedData + "." + sig64, nil
}

// ParseAndVerifyToken 校验并解析管理员 Token
func ParseAndVerifyToken(signingKey []byte, tokenString string) (*Claims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrTokenMalformed
	}

	signedData := parts[0] + "." + parts[1]
	providedSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrTokenMalformed
	}

	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(signedData))
	expectedSig := mac.Sum(nil)

	if subtle.ConstantTimeCompare(providedSig, expectedSig) != 1 {
		return nil, ErrSignatureInvalid
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrTokenMalformed
	}

	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	// 校验会话有效期
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, ErrTokenExpired
	}

	return &claims, nil
}
