package logger

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestInitGlobalLogger(t *testing.T) {
	buf := new(bytes.Buffer)
	cfg := Config{
		Level:     "debug",
		Format:    "json",
		AddSource: false,
	}

	l := InitGlobalLogger(cfg, buf)
	if l == nil {
		t.Fatal("expected logger to be initialized")
	}

	Info("test message", "component", "test", "num", 42)

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Fatalf("expected log output to contain message, got: %s", output)
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(output), &data); err != nil {
		t.Fatalf("expected valid JSON log output, got: %v", err)
	}

	if data["msg"] != "test message" || data["component"] != "test" {
		t.Fatalf("unexpected fields in json: %+v", data)
	}
}
