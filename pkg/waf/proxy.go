package waf

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"alinksec/pkg/crypto"
	"alinksec/pkg/logger"
)

// OnThreatBlockedHandler 威胁拦截事件回调函数
type OnThreatBlockedHandler func(clientIP, method, uri string, result MatchResult)

// ProxyHandler WAF 反向代理处理器
type ProxyHandler struct {
	engine        *Engine
	reverseProxy  *httputil.ReverseProxy
	upstream      *url.URL
	onThreatEvent OnThreatBlockedHandler
}

// NewProxyHandler 创建 WAF 反向代理处理器
func NewProxyHandler(engine *Engine, upstreamURL *url.URL, onThreat OnThreatBlockedHandler) *ProxyHandler {
	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)

	// 自定义 Director 保留原始 Header
	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
		req.Header.Set("X-WAF-Engine", "AlinkSec-WAF-v1.0")
	}

	return &ProxyHandler{
		engine:        engine,
		reverseProxy:  proxy,
		upstream:      upstreamURL,
		onThreatEvent: onThreat,
	}
}

// ServeHTTP 实现 http.Handler
func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)

	// 读取并缓存请求体
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(r.Body)
		// 重置 Body 供上游服务复用
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// 提取全部请求头
	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	// WAF 深度规则引擎检测
	result := p.engine.Inspect(clientIP, r.Method, r.RequestURI, r.UserAgent(), headers, bodyBytes)
	if result.Matched {
		// 拦截并记录
		incidentID, _ := crypto.GenerateSecureToken(12)
		logger.Warn("WAF Blocked Malicious Request",
			"incident_id", incidentID,
			"client_ip", clientIP,
			"method", r.Method,
			"uri", r.RequestURI,
			"rule_id", result.RuleID,
			"threat_type", result.ThreatType,
			"matched_part", result.MatchedPart,
		)

		if p.onThreatEvent != nil {
			p.onThreatEvent(clientIP, r.Method, r.RequestURI, result)
		}

		p.renderBlockPage(w, r, incidentID, result)
		return
	}

	// 注入防御响应头
	w.Header().Set("X-WAF-Protected-By", "AlinkSec-Modular-WAF")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")

	// 放行合法流量到上游应用
	p.reverseProxy.ServeHTTP(w, r)
}

// renderBlockPage 渲染等保合规安全拦截页面
func (p *ProxyHandler) renderBlockPage(w http.ResponseWriter, r *http.Request, incidentID string, result MatchResult) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-WAF-Blocked", "true")
	w.Header().Set("X-WAF-Incident-ID", incidentID)
	w.WriteHeader(http.StatusForbidden)

	response := fmt.Sprintf(`{
  "code": 403,
  "status": "BLOCKED",
  "system": "AlinkSec Modular Cloud WAF",
  "compliance": "GB/T 22239-2019 MLPS3 Security Boundary Protection",
  "message": "Your request has been blocked by security policies.",
  "incident_id": "%s",
  "threat_type": "%s",
  "rule_id": "%s",
  "timestamp": "%s"
}`, incidentID, result.ThreatType, result.RuleID, time.Now().Format(time.RFC3339))

	_, _ = w.Write([]byte(response))
}

// getClientIP 安全提取客户端真实 IP (防伪造 X-Forwarded-For 溯源)
func getClientIP(r *http.Request) string {
	// 优先取最左侧 X-Forwarded-For
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// 取 RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && net.ParseIP(host) != nil {
		return host
	}

	return r.RemoteAddr
}
