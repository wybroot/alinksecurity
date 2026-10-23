package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

// RFC 6238 TOTP (Time-Based One-Time Password Algorithm)
// 默认步长 30 秒，6 位数字，使用 SHA-1 (兼顾 Google Authenticator / 腾讯身份验证器 等移动端标准)

const (
	defaultStepSeconds = 30
	defaultDigits      = 6
)

// GenerateTOTPSecret 生成等保2.0合规的随机 Base32 TOTP 密钥 (160-bit / 20 bytes)
func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate random secret: %w", err)
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)
	return strings.ToUpper(secret), nil
}

// GenerateTOTPCode 根据密钥和时间计算当前的 TOTP 6 位验证码
func GenerateTOTPCode(secret string, t time.Time) (string, error) {
	secret = strings.TrimSpace(strings.ToUpper(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("invalid base32 secret: %w", err)
	}

	counter := uint64(t.Unix() / defaultStepSeconds)
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)

	// HMAC-SHA1
	mac := hmac.New(sha1.New, key)
	mac.Write(counterBytes[:])
	hash := mac.Sum(nil)

	// Dynamic Truncation (RFC 4226 Section 5.4)
	offset := hash[len(hash)-1] & 0x0F
	truncated := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7FFFFFFF
	codeInt := truncated % uint32(math.Pow10(defaultDigits))

	return fmt.Sprintf("%0*d", defaultDigits, codeInt), nil
}

// VerifyTOTPCode 校验用户输入的 TOTP 验证码 (容忍前后 1 个时间步长，即 ±30s 偏差)
func VerifyTOTPCode(secret, userCode string) bool {
	userCode = strings.TrimSpace(userCode)
	if len(userCode) != defaultDigits {
		return false
	}

	now := time.Now()
	// 校验当前时间窗口、前一个窗口、后一个窗口
	windows := []time.Time{
		now,
		now.Add(-defaultStepSeconds * time.Second),
		now.Add(defaultStepSeconds * time.Second),
	}

	for _, w := range windows {
		expectedCode, err := GenerateTOTPCode(secret, w)
		if err != nil {
			return false
		}
		// 使用常量时间比较，防止时序侧信道攻击 (Timing Attack)
		if subtle.ConstantTimeCompare([]byte(userCode), []byte(expectedCode)) == 1 {
			return true
		}
	}

	return false
}

// BuildTOTPURI 生成与 Google Authenticator / 腾讯身份验证器兼容的 otpauth:// 规范 URI
func BuildTOTPURI(secret, username, issuer string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, username, secret, issuer)
}
