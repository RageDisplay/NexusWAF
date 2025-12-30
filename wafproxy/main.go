package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

type WAFProxy struct {
	target         *url.URL
	proxy          *httputil.ReverseProxy
	redisClient    *redis.Client
	analyzerClient *http.Client
	config         *AppConfig
	currentPort    string
}

type AppConfig struct {
	TargetURL  string `json:"target_url"`
	ListenPort string `json:"listen_port"`
	EnableSQLi bool   `json:"enable_sqli"`
	EnableXSS  bool   `json:"enable_xss"`
	EnableCMDi bool   `json:"enable_cmdi"`
	EnablePath bool   `json:"enable_path"`
}

type AnalysisRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

type AnalysisResponse struct {
	ThreatLevel int      `json:"threat_level"`
	Matches     []string `json:"matches,omitempty"`
	Action      string   `json:"action"`
}

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Threats   []string  `json:"threats"`
	Action    string    `json:"action"`
}

func NewWAFProxy(target string, redisAddr string) (*WAFProxy, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: "",
		DB:       0,
	})

	currentPort := os.Getenv("PORT")
	if currentPort == "" {
		currentPort = "8081"
	}

	p := &WAFProxy{
		target:         u,
		proxy:          httputil.NewSingleHostReverseProxy(u),
		redisClient:    rdb,
		analyzerClient: &http.Client{Timeout: 500 * time.Millisecond},
		currentPort:    currentPort,
	}

	p.proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.Request.Method == http.MethodPost || resp.Request.Method == http.MethodPut {
			resp.Header.Del("Content-Length")
		}
		return nil
	}

	originalDirector := p.proxy.Director
	p.proxy.Director = func(req *http.Request) {
		originalDirector(req)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			bodyBytes, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
	}

	return p, nil
}

func (p *WAFProxy) checkRequest(r *http.Request) (bool, []string) {
	var threats []string

	// Декодируем URL
	fullURL := r.URL.String() + " " + r.URL.RawQuery
	decodedURL, _ := url.QueryUnescape(fullURL)
	log.Printf("Checking URL (decoded): %s", decodedURL)

	if threatsFound := p.checkPatterns(decodedURL, "url", r); len(threatsFound) > 0 {
		threats = append(threats, threatsFound...)
	}

	// Check headers
	for name, values := range r.Header {
		if p.isSuspiciousHeader(name) {
			for _, value := range values {
				if threatsFound := p.checkPatterns(name+": "+value, "header", r); len(threatsFound) > 0 {
					threats = append(threats, threatsFound...)
				}
			}
		}
	}

	// Check body for POST/PUT
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return true, []string{"invalid request body"}
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		bodyStr := string(bodyBytes)

		// Если это form data, декодируем её
		if strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			decodedBody, _ := url.QueryUnescape(bodyStr)
			log.Printf("Checking body (decoded): %s", decodedBody)
			if threatsFound := p.checkPatterns(decodedBody, "body", r); len(threatsFound) > 0 {
				threats = append(threats, threatsFound...)
			}
		} else {
			log.Printf("Checking body: %s", bodyStr)
			if threatsFound := p.checkPatterns(bodyStr, "body", r); len(threatsFound) > 0 {
				threats = append(threats, threatsFound...)
			}
		}
	}

	log.Printf("Total threats found: %d", len(threats))
	return len(threats) > 0, threats
}

func (p *WAFProxy) isSuspiciousHeader(name string) bool {
	suspiciousHeaders := []string{
		"user-agent", "referer", "origin", "cookie",
		"x-forwarded-for", "x-real-ip", "authorization",
	}

	nameLower := strings.ToLower(name)
	for _, header := range suspiciousHeaders {
		if strings.Contains(nameLower, header) {
			return true
		}
	}
	return false
}

func (p *WAFProxy) checkPatterns(input, inputType string, r *http.Request) []string {
	ctx := context.Background()
	var threats []string

	categories := []struct {
		name    string
		enabled bool
		key     string
	}{
		{"sqli", p.config != nil && p.config.EnableSQLi, "waf:sqli"},
		{"xss", p.config != nil && p.config.EnableXSS, "waf:xss"},
		{"cmdi", p.config != nil && p.config.EnableCMDi, "waf:cmdi"},
		{"pathtraversal", p.config != nil && p.config.EnablePath, "waf:pathtraversal"},
	}

	for _, category := range categories {
		if !category.enabled {
			continue
		}

		patterns, err := p.redisClient.SMembers(ctx, category.key).Result()
		if err != nil {
			log.Printf("Error getting patterns for %s: %v", category.name, err)
			continue
		}

		for _, pattern := range patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				log.Printf("Error compiling pattern %s: %v", pattern, err)
				continue
			}

			matches := re.FindStringSubmatch(input)
			if matches != nil {
				log.Printf("PATTERN MATCHED! Category: %s, Pattern: %s, Input: %s",
					category.name, pattern, input)

				// False positive проверки
				if p.isFalsePositive(input, category.name, pattern, inputType) {
					log.Printf("False positive, skipping")
					continue
				}
				threats = append(threats, category.name+": "+pattern)
				p.updateStats(category.name, r)
			}
		}
	}

	return threats
}

func (p *WAFProxy) isFalsePositive(input, category, pattern, inputType string) bool {
	inputLower := strings.ToLower(input)

	// Для SQLi: разрешаем простые параметры в URL
	if category == "sqli" && inputType == "url" {
		// Разрешаем очень короткие безопасные параметры
		if len(input) < 10 && regexp.MustCompile(`^[a-z0-9=&?\-_\.]+$`).MatchString(inputLower) {
			return true
		}
		// Разрешаем обычные параметры типа id=123
		if regexp.MustCompile(`^(id|name|page|size|search|q)=[a-z0-9]+$`).MatchString(inputLower) {
			return true
		}
	}

	// Для Command Injection в заголовках: игнорируем quality values (;q=0.9)
	if category == "cmdi" && inputType == "header" {
		if strings.Contains(inputLower, ";q=") {
			return true
		}
	}

	return false
}

func (p *WAFProxy) updateStats(threatType string, r *http.Request) {
	ctx := context.Background()

	p.redisClient.Incr(ctx, "waf:stats:total_requests")
	p.redisClient.Incr(ctx, "waf:stats:blocked_requests")
	p.redisClient.Incr(ctx, "waf:stats:threats:"+threatType)

	ip := getClientIP(r)

	method := ""
	urlStr := ""
	if r != nil {
		method = r.Method
		if r.URL != nil {
			urlStr = r.URL.RequestURI()
		}
	}

	if method == "" {
		method = "UNKNOWN"
	}
	if urlStr == "" {
		urlStr = "/"
	}

	logEntry := LogEntry{
		Timestamp: time.Now(),
		IP:        ip,
		Method:    method,
		URL:       urlStr,
		Threats:   []string{threatType},
		Action:    "block",
	}

	logData, _ := json.Marshal(logEntry)
	p.redisClient.LPush(ctx, "waf:logs", logData)
	p.redisClient.LTrim(ctx, "waf:logs", 0, 999)
}

// getClientIP пытается извлечь реальный IP клиента, обходя Docker bridge (172.16.0.0/12)
func getClientIP(r *http.Request) string {
	if r == nil {
		return "unknown"
	}

	// Попробуем X-Forwarded-For (список IP: client, proxy1, proxy2)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		// Ищем первый приемлемый IP (не принадлежащий Docker-bridge и не loopback)
		for _, p := range parts {
			ip := strings.TrimSpace(p)
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue
			}
			if isDockerBridgeIP(parsed) || parsed.IsLoopback() {
				continue
			}
			return ip
		}
		// Если ничего подходящего не найдено — вернём первый элемент
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	// Попробуем X-Real-IP
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return strings.TrimSpace(xr)
	}

	// fallback — RemoteAddr без порта
	addr := r.RemoteAddr
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func isDockerBridgeIP(ip net.IP) bool {
	// Проверим диапазон 172.16.0.0/12 (включает 172.17.*, 172.18.*, 172.19.* и т.д.)
	_, dockerNet, _ := net.ParseCIDR("172.16.0.0/12")
	return dockerNet.Contains(ip)
}

func (p *WAFProxy) updateTotalRequests() {
	ctx := context.Background()
	p.redisClient.Incr(ctx, "waf:stats:total_requests")
}

func (p *WAFProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.updateTotalRequests()

	log.Printf("=== NEW REQUEST ===")
	log.Printf("Method: %s, URL: %s", r.Method, r.URL.String())

	// Check with pattern matching
	if isBlocked, threats := p.checkRequest(r); isBlocked {
		log.Printf("Request blocked by WAF. Threats: %v", threats)
		http.Error(w, "Request blocked by WAF", http.StatusForbidden)
		return
	}

	log.Printf("Request allowed, proxying to target")
	p.proxy.ServeHTTP(w, r)
}

func (p *WAFProxy) loadConfig() {
	ctx := context.Background()

	data, err := p.redisClient.Get(ctx, "waf:config").Result()
	if err != nil {
		log.Printf("Error loading config from Redis: %v", err)
		p.config = &AppConfig{
			TargetURL:  "http://192.168.200.50:7000",
			ListenPort: "8081",
			EnableSQLi: true,
			EnableXSS:  true,
			EnableCMDi: true,
			EnablePath: true,
		}
		return
	}

	var config AppConfig
	if err := json.Unmarshal([]byte(data), &config); err != nil {
		log.Printf("Error parsing config: %v", err)
		return
	}

	p.config = &config
	log.Printf("Loaded config: SQLi=%t, XSS=%t, CMDi=%t, Path=%t",
		config.EnableSQLi, config.EnableXSS, config.EnableCMDi, config.EnablePath)

	// Проверяем изменение целевого URL
	if config.TargetURL != "" && config.TargetURL != p.target.String() {
		newTarget, err := url.Parse(config.TargetURL)
		if err == nil {
			p.target = newTarget
			p.proxy = httputil.NewSingleHostReverseProxy(newTarget)
			log.Printf("Updated target URL to: %s", config.TargetURL)
		}
	}

	// Проверяем изменение порта и переконфигурируем контейнер Docker
	if config.ListenPort != "" && config.ListenPort != p.currentPort {
		log.Printf("Port change detected: %s -> %s", p.currentPort, config.ListenPort)
		oldPort := p.currentPort
		p.currentPort = config.ListenPort

		// Используем Redis для сигнализации демону на хосте
		go func() {
			if err := updateContainerPort(p.redisClient, oldPort, config.ListenPort); err != nil {
				log.Printf("Error updating container port: %v", err)
				// Откатываем изменение в случае ошибки
				p.currentPort = oldPort
			}
		}()
	}
}

func (p *WAFProxy) startConfigWatcher() {
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for range ticker.C {
			p.loadConfig()
		}
	}()
}

// updateContainerPort записывает требуемый порт в Redis для демона на хосте
// Демон (waf-port-monitor.py) отслеживает изменения и пересоздает контейнер
func updateContainerPort(rdb *redis.Client, oldPort, newPort string) error {
	ctx := context.Background()
	redisKey := "waf:port:requested"

	log.Printf("Writing port request to Redis: %s", redisKey)

	// Сохраняем требуемый порт в Redis для сигнализации демону
	if err := rdb.Set(ctx, redisKey, newPort, 0).Err(); err != nil {
		log.Printf("Error saving port request to Redis: %v", err)
		return err
	}

	log.Printf("Port request saved to Redis. Waiting for host daemon to apply changes...")
	log.Printf("Demоn (waf-port-monitor.py) will execute: docker-compose up -d --force-recreate --no-deps wafproxy")

	return nil
}

func main() {
	target := os.Getenv("TARGET_URL")
	if target == "" {
		target = "http://192.168.200.50:7000"
	}

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "redis:6379"
	}

	proxy, err := NewWAFProxy(target, redisAddr)
	if err != nil {
		log.Fatal(err)
	}

	proxy.loadConfig()
	proxy.startConfigWatcher()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	log.Printf("WAF Proxy started on :%s, protecting %s", port, target)
	log.Fatal(http.ListenAndServe(":"+port, proxy))
}
