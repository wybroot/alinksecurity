package waf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestWAFProxyAndDetectionPipeline(t *testing.T) {
	// 1. 模拟后端真实 Web 应用 (Upstream)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Backend-Processed", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response: " + string(body)))
	}))
	defer backend.Close()

	upstreamURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	engine := NewEngine()
	// 设置测试限流阈值
	engine.rateLimiter = NewRateLimiter(5, 5*time.Second)

	proxyHandler := NewProxyHandler(engine, upstreamURL, nil)

	// 测试辅助调用函数
	sendRequest := func(clientIP, method, targetURI, userAgent, bodyStr string) (*http.Response, map[string]any) {
		req := httptest.NewRequest(method, targetURI, bytes.NewBufferString(bodyStr))
		if clientIP != "" {
			req.RemoteAddr = clientIP + ":12345"
		}
		if userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
		}
		w := httptest.NewRecorder()
		proxyHandler.ServeHTTP(w, req)
		resp := w.Result()

		var blockBody map[string]any
		if resp.StatusCode == http.StatusForbidden {
			_ = json.Unmarshal(w.Body.Bytes(), &blockBody)
		}
		return resp, blockBody
	}

	// Case 1: 正常合法 GET 请求 -> 正常放行通过 (200 OK)
	resp, _ := sendRequest("198.51.100.1", "GET", "/api/v1/products?category=books", "Mozilla/5.0", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for clean request, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Backend-Processed") != "true" {
		t.Fatal("expected request to reach backend")
	}

	// Case 2: 正常合法 POST 请求 -> 正常放行通过 (200 OK)
	resp, _ = sendRequest("198.51.100.2", "POST", "/api/v1/orders", "Mozilla/5.0", `{"item_id": 123, "qty": 1}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for clean POST request, got %d", resp.StatusCode)
	}

	// Case 3: SQL 注入反向代理拦截 -> 403 Forbidden
	resp, blockData := sendRequest("198.51.100.3", "GET", "/users?id=1%20union%20select%201,2,password%20from%20admin", "Mozilla/5.0", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for SQLi, got %d", resp.StatusCode)
	}
	if blockData["threat_type"] != string(ThreatSQLi) {
		t.Fatalf("expected SQL_INJECTION threat, got %v", blockData["threat_type"])
	}

	// Case 4: XSS 跨站脚本拦截 -> 403 Forbidden
	resp, blockData = sendRequest("198.51.100.4", "POST", "/submit", "Mozilla/5.0", `<script>alert(document.cookie)</script>`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for XSS in Body, got %d", resp.StatusCode)
	}
	if blockData["threat_type"] != string(ThreatXSS) {
		t.Fatalf("expected CROSS_SITE_SCRIPTING threat, got %v", blockData["threat_type"])
	}

	// Case 5: 目录穿越 / LFI 拦截 -> 403 Forbidden
	resp, blockData = sendRequest("198.51.100.5", "GET", "/download?file=../../../../etc/passwd", "Mozilla/5.0", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for Path Traversal, got %d", resp.StatusCode)
	}
	if blockData["threat_type"] != string(ThreatPathTraversal) {
		t.Fatalf("expected PATH_TRAVERSAL threat, got %v", blockData["threat_type"])
	}

	// Case 6: 命令注入 RCE 拦截 -> 403 Forbidden
	resp, blockData = sendRequest("198.51.100.6", "GET", "/ping?target=127.0.0.1;%20whoami", "Mozilla/5.0", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for RCE, got %d", resp.StatusCode)
	}
	if blockData["threat_type"] != string(ThreatRCE) {
		t.Fatalf("expected COMMAND_INJECTION threat, got %v", blockData["threat_type"])
	}

	// Case 7: 扫描器 User-Agent 特征拦截 -> 403 Forbidden
	resp, blockData = sendRequest("198.51.100.7", "GET", "/index.php", "sqlmap/1.5#stable", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for sqlmap scanner, got %d", resp.StatusCode)
	}
	if blockData["threat_type"] != string(ThreatScanner) {
		t.Fatalf("expected MALICIOUS_SCANNER threat, got %v", blockData["threat_type"])
	}

	// Case 8: 双重 URL 编码绕过攻击拦截 -> 403 Forbidden
	// %252e%252e%252f 是 ../ 的双重编码
	resp, blockData = sendRequest("198.51.100.8", "GET", "/view?path=%252e%252e%252f%252e%252e%252fetc%252fpasswd", "Mozilla/5.0", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for double encoded traversal, got %d", resp.StatusCode)
	}
	if blockData["threat_type"] != string(ThreatPathTraversal) {
		t.Fatalf("expected PATH_TRAVERSAL, got %v", blockData["threat_type"])
	}

	// Case 9: CC 频控限流测试 (单 IP 阈值 5 次，第 6 次触发阻断)
	ccIP := "203.0.113.200"
	for i := 0; i < 5; i++ {
		r, _ := sendRequest(ccIP, "GET", fmt.Sprintf("/hello?q=%d", i), "Mozilla/5.0", "")
		if r.StatusCode != http.StatusOK {
			t.Fatalf("request %d should be allowed, got %d", i+1, r.StatusCode)
		}
	}
	// 第 6 次应当被 CC 拦截
	ccResp, ccBlock := sendRequest(ccIP, "GET", "/hello?q=overflow", "Mozilla/5.0", "")
	if ccResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for rate limit exceeded, got %d", ccResp.StatusCode)
	}
	if ccBlock["rule_id"] != "WAF-CC-LIMIT" {
		t.Fatalf("expected WAF-CC-LIMIT rule, got %v", ccBlock["rule_id"])
	}
}
