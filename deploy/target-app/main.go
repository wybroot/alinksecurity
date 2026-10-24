package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// VulnerableApp 靶机应用：模拟企业在线业务系统 (用于验证 WAF/EDR/Tamper 真实防护)
func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()

	// 1. 业务首页
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Enterprise Business Portal (Target System)</title></head>
<body style="font-family:sans-serif;padding:2rem;">
  <h2>🏦 企业核心生产业务系统 (Vulnerable Target App)</h2>
  <p>该系统部署于内网 APP 区域，受边缘云 WAF 与主机探针保护。</p>
  <ul>
    <li><a href="/api/health">系统健康探活 /api/health</a></li>
    <li><a href="/api/products?q=laptop">商品搜索接口 /api/products?q=laptop</a></li>
  </ul>
</body>
</html>`)
	})

	// 2. 健康探活
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "UP",
			"timestamp": time.Now().Unix(),
			"app":       "target-production-webapp",
			"tier":      "Tier 2 Important Asset",
		})
	})

	// 3. 模拟数据查询 (存在潜在 SQL 注入漏洞点，由上游 WAF 进行阻断)
	mux.HandleFunc("/api/products", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"query":   q,
			"results": []string{"Product A", "Product B", "Product C"},
			"count":   3,
			"note":    "Query processed successfully by backend",
		})
	})

	// 4. 模拟文件上传 (Webshell 上传场景)
	mux.HandleFunc("/api/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "uploaded",
			"bytes":   len(body),
			"message": "File received by backend server",
		})
	})

	addr := ":" + port
	log.Printf("[TARGET-APP] Enterprise Target App started listening on %s...", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
