package auth

import (
	"testing"
	"time"
)

func TestTOTPGenerationAndVerification(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("failed to generate totp secret: %v", err)
	}

	if len(secret) < 16 {
		t.Fatalf("secret too short: %s", secret)
	}

	now := time.Now()
	code, err := GenerateTOTPCode(secret, now)
	if err != nil {
		t.Fatalf("failed to generate totp code: %v", err)
	}

	if len(code) != 6 {
		t.Fatalf("expected 6 digits code, got %s", code)
	}

	// 1. 验证当前验证码
	if !VerifyTOTPCode(secret, code) {
		t.Fatalf("expected code %s to be valid", code)
	}

	// 2. 验证错误验证码
	if VerifyTOTPCode(secret, "000000") && code != "000000" {
		t.Fatal("expected arbitrary code to be rejected")
	}

	// 3. 验证时间漂移 (25秒前，在容忍窗口内)
	pastCode, err := GenerateTOTPCode(secret, now.Add(-25*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyTOTPCode(secret, pastCode) {
		t.Fatal("expected past code within 30s step to be accepted")
	}

	// 4. 验证超出时间窗口 (超过 120 秒前)
	tooOldCode, err := GenerateTOTPCode(secret, now.Add(-120*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if VerifyTOTPCode(secret, tooOldCode) && tooOldCode != code {
		t.Fatal("expected expired code outside window to be rejected")
	}

	// 5. 验证 URI 格式
	uri := BuildTOTPURI(secret, "secadmin", "AlinkSec")
	if uri == "" || len(uri) < 30 {
		t.Fatalf("invalid uri generated: %s", uri)
	}
}
