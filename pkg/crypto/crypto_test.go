package crypto

import (
	"testing"
)

func TestSHA256(t *testing.T) {
	data := "hello alinksecurity"
	hash1 := SHA256String(data)
	hash2 := SHA256Bytes([]byte(data))

	if hash1 != hash2 {
		t.Fatalf("expected matching hashes, got %s and %s", hash1, hash2)
	}

	if len(hash1) != 64 {
		t.Fatalf("expected 64 hex characters, got %d", len(hash1))
	}
}

func TestComputeChainedHash(t *testing.T) {
	genesis := "0000000000000000000000000000000000000000000000000000000000000000"
	log1 := []byte(`{"event_id":"evt_001","action":"login_success"}`)
	h1 := ComputeChainedHash(genesis, log1)

	log2 := []byte(`{"event_id":"evt_002","action":"privilege_escalation"}`)
	h2 := ComputeChainedHash(h1, log2)

	if h1 == h2 || len(h1) != 64 || len(h2) != 64 {
		t.Fatalf("chained hash calculation failed: h1=%s, h2=%s", h1, h2)
	}

	// Verify tampering detection
	tamperedLog1 := []byte(`{"event_id":"evt_001","action":"login_failed"}`)
	tamperedH1 := ComputeChainedHash(genesis, tamperedLog1)
	if tamperedH1 == h1 {
		t.Fatal("tampered log produced same hash!")
	}
}

func TestGenerateSecureToken(t *testing.T) {
	token1, err := GenerateSecureToken(16)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	if len(token1) != 32 {
		t.Fatalf("expected 32 hex chars for 16 bytes, got %d", len(token1))
	}

	token2, err := GenerateSecureToken(16)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	if token1 == token2 {
		t.Fatal("expected distinct random tokens")
	}
}

func TestPasswordHash(t *testing.T) {
	pwd := "AlinkSec@2026!Strict"
	hash, err := HashPassword(pwd)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	if !CheckPasswordHash(pwd, hash) {
		t.Fatal("password verification failed for correct password")
	}

	if CheckPasswordHash("WrongPassword@123", hash) {
		t.Fatal("password verification succeeded for incorrect password")
	}
}
