package tamper

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTamperDetectionAndInstantReversion(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tamper_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	watchDir := filepath.Join(tempDir, "wwwroot")
	backupDir := filepath.Join(tempDir, "safe_vault")
	_ = os.MkdirAll(watchDir, 0755)

	// 1. 初始化合法 Web 资产文件
	indexPath := filepath.Join(watchDir, "index.html")
	origIndexContent := "<html><body><h1>Welcome to Enterprise Portal</h1></body></html>"
	if err := os.WriteFile(indexPath, []byte(origIndexContent), 0644); err != nil {
		t.Fatal(err)
	}

	jsDir := filepath.Join(watchDir, "js")
	_ = os.MkdirAll(jsDir, 0755)
	jsPath := filepath.Join(jsDir, "app.js")
	origJsContent := "console.log('portal app loaded');"
	if err := os.WriteFile(jsPath, []byte(origJsContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. 初始化防篡改引擎
	vault, err := NewBaselineVault(watchDir, backupDir, []string{".html", ".js", ".php"})
	if err != nil {
		t.Fatal(err)
	}

	if err := vault.BuildBaseline(); err != nil {
		t.Fatal(err)
	}

	// 验证基线已正确建立
	if _, ok := vault.GetRecord("index.html"); !ok {
		t.Fatal("expected index.html in baseline")
	}

	var eventsMu sync.Mutex
	var events []TamperEvent

	watcher, err := NewWatcher(vault, watchDir, true, []string{".html", ".js", ".php"}, func(evt TamperEvent) {
		eventsMu.Lock()
		defer eventsMu.Unlock()
		events = append(events, evt)
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := watcher.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()

	// 等待文件系统监听器挂载就绪
	time.Sleep(200 * time.Millisecond)

	// Case 1: 模拟非法篡改 index.html (注入黑产挂马代码)
	maliciousHTML := "<html><body><h1>Hacked by Anonymous</h1></body></html>"
	if err := os.WriteFile(indexPath, []byte(maliciousHTML), 0644); err != nil {
		t.Fatal(err)
	}

	// 等待自愈触发 (通常毫秒级)
	time.Sleep(300 * time.Millisecond)

	// 验证 index.html 已被毫秒级自愈复原
	restoredContent, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restoredContent) != origIndexContent {
		t.Fatalf("auto-revert failed! Content is still corrupted: %s", string(restoredContent))
	}

	// Case 2: 模拟非法删除核心脚本 app.js
	if err := os.Remove(jsPath); err != nil {
		t.Fatal(err)
	}

	time.Sleep(300 * time.Millisecond)

	// 验证被删除的 js 文件已被自愈库重新还原
	restoredJS, err := os.ReadFile(jsPath)
	if err != nil {
		t.Fatalf("auto-revert for deleted file failed! File missing: %v", err)
	}
	if string(restoredJS) != origJsContent {
		t.Fatalf("restored JS does not match original: %s", string(restoredJS))
	}

	// Case 3: 模拟攻击者非法上传未经授权脚本文件 (backdoor.php)
	backdoorPath := filepath.Join(watchDir, "backdoor.php")
	if err := os.WriteFile(backdoorPath, []byte("<?php echo 'unauthorized file payload'; ?>"), 0644); err != nil {
		t.Fatal(err)
	}

	time.Sleep(300 * time.Millisecond)

	// 验证未经授权的文件已被自动隔离清除
	if _, err := os.Stat(backdoorPath); !os.IsNotExist(err) {
		t.Fatal("unauthorized file was not quarantined!")
	}

	// 验证捕获到的篡改事件记录
	eventsMu.Lock()
	defer eventsMu.Unlock()
	if len(events) < 3 {
		t.Fatalf("expected at least 3 tamper events, got %d", len(events))
	}

	var foundModified, foundDeleted, foundCreated bool
	for _, e := range events {
		if e.Action == ActionModified && strings.Contains(e.FilePath, "index.html") {
			foundModified = true
		}
		if e.Action == ActionDeleted && strings.Contains(e.FilePath, "app.js") {
			foundDeleted = true
		}
		if e.Action == ActionCreated && strings.Contains(e.FilePath, "backdoor.php") {
			foundCreated = true
		}
	}

	if !foundModified || !foundDeleted || !foundCreated {
		t.Fatalf("missing events: modified=%v, deleted=%v, created=%v", foundModified, foundDeleted, foundCreated)
	}
}
