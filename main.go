package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	version          = "subconverter-modern v0.2.0"
	defaultListen    = ":25500"
	defaultTestURL   = "http://www.gstatic.com/generate_204"
	defaultUserAgent = "SubConverter-Modern/0.2"
	maxBodyBytes     = 12 << 20
)

var lanRules = []string{
	"DOMAIN,localhost,DIRECT",
	"DOMAIN-SUFFIX,local,DIRECT",
	"DOMAIN-SUFFIX,lan,DIRECT",
	"IP-CIDR,0.0.0.0/8,DIRECT,no-resolve",
	"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
	"IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
	"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
	"IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
	"IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
	"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
	"IP-CIDR,224.0.0.0/4,DIRECT,no-resolve",
	"IP-CIDR6,fc00::/7,DIRECT,no-resolve",
	"IP-CIDR6,fe80::/10,DIRECT,no-resolve",
}

type server struct {
	client           *http.Client
	defaultConfigURL string
}

type mihomoConfig struct {
	MixedPort               int                     `yaml:"mixed-port"`
	AllowLAN                bool                    `yaml:"allow-lan"`
	Mode                    string                  `yaml:"mode"`
	LogLevel                string                  `yaml:"log-level"`
	IPv6                    bool                    `yaml:"ipv6"`
	TCPConcurrent           bool                    `yaml:"tcp-concurrent"`
	GlobalClientFingerprint string                  `yaml:"global-client-fingerprint"`
	Profile                 profileConfig           `yaml:"profile"`
	DNS                     dnsConfig               `yaml:"dns"`
	Proxies                 []map[string]any        `yaml:"proxies"`
	ProxyGroups             []proxyGroup            `yaml:"proxy-groups"`
	RuleProviders           map[string]ruleProvider `yaml:"rule-providers,omitempty"`
	Rules                   []string                `yaml:"rules"`
}

type profileConfig struct {
	StoreSelected bool `yaml:"store-selected"`
	StoreFakeIP   bool `yaml:"store-fake-ip"`
}

type dnsConfig struct {
	Enable            bool     `yaml:"enable"`
	IPv6              bool     `yaml:"ipv6"`
	EnhancedMode      string   `yaml:"enhanced-mode"`
	FakeIPRange       string   `yaml:"fake-ip-range"`
	DefaultNameserver []string `yaml:"default-nameserver"`
	Nameserver        []string `yaml:"nameserver"`
	FakeIPFilter      []string `yaml:"fake-ip-filter"`
}

type proxyGroup struct {
	Name      string   `yaml:"name"`
	Type      string   `yaml:"type"`
	URL       string   `yaml:"url,omitempty"`
	Interval  int      `yaml:"interval,omitempty"`
	Tolerance int      `yaml:"tolerance,omitempty"`
	Proxies   []string `yaml:"proxies"`
}

type ruleProvider struct {
	Type     string `yaml:"type"`
	Behavior string `yaml:"behavior"`
	URL      string `yaml:"url"`
	Path     string `yaml:"path"`
	Interval int    `yaml:"interval"`
}

type parsedTemplate struct {
	Groups        []proxyGroup
	RuleProviders map[string]ruleProvider
	Rules         []string
}

type renderResult struct {
	Body        []byte
	ContentType string
	Extension   string
	Renderer    string
}

type singBoxConfig struct {
	Log          map[string]any   `json:"log"`
	DNS          map[string]any   `json:"dns"`
	Inbounds     []map[string]any `json:"inbounds,omitempty"`
	Outbounds    []map[string]any `json:"outbounds"`
	Route        map[string]any   `json:"route"`
	Experimental map[string]any   `json:"experimental,omitempty"`
}

func main() {
	s := &server{
		client: &http.Client{
			Timeout: 45 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 20 * time.Second,
				IdleConnTimeout:       60 * time.Second,
			},
		},
		defaultConfigURL: os.Getenv("DEFAULT_CONFIG_URL"),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/version", s.handleVersion)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/sub", s.handleSub)
	mux.HandleFunc("/refreshrules", s.handleNoop)
	mux.HandleFunc("/updateconf", s.handleNoop)
	mux.HandleFunc("/readconf", s.handleReadconf)

	listen := os.Getenv("LISTEN_ADDR")
	if listen == "" {
		listen = defaultListen
	}

	log.Printf("%s listening on %s", version, listen)
	if err := http.ListenAndServe(listen, mux); err != nil {
		log.Fatal(err)
	}
}

func (s *server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("content-type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintln(w, version)
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"service": version,
	})
}

func (s *server) handleNoop(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("content-type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintln(w, "OK")
}

func (s *server) handleReadconf(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("content-type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintln(w, "modern-subconverter uses external config URLs and does not expose mutable runtime config")
}

func (s *server) handleSub(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	target := strings.ToLower(query.Get("target"))
	if target == "" {
		target = "clash"
	}
	if !isSupportedTarget(target) {
		writeError(w, http.StatusBadRequest, "unsupported target")
		return
	}

	sourceURL := query.Get("url")
	if sourceURL == "" {
		writeError(w, http.StatusBadRequest, "missing url")
		return
	}

	configURL := query.Get("config")
	if configURL == "" {
		configURL = s.defaultConfigURL
	}

	proxies, err := s.loadProxies(sourceURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	templateText := ""
	if configURL != "" {
		templateText, err = s.fetchText(configURL)
		if err != nil {
			writeError(w, http.StatusBadGateway, "config fetch failed")
			return
		}
	}

	parsed := parseTemplate(templateText, proxyNames(proxies))
	rendered, err := renderTarget(target, proxies, parsed)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	filename := query.Get("filename")
	if filename == "" {
		filename = "SubConverterModern"
	}
	w.Header().Set("content-type", rendered.ContentType)
	w.Header().Set("content-disposition", fmt.Sprintf(`attachment; filename="%s.%s"`, safeFilename(filename), rendered.Extension))
	w.Header().Set("cache-control", "no-store")
	w.Header().Set("x-content-type-options", "nosniff")
	w.Header().Set("x-subconverter-renderer", rendered.Renderer)
	_, _ = w.Write(rendered.Body)
}

func isSupportedTarget(target string) bool {
	switch normalizeTarget(target) {
	case "mihomo", "singbox", "uri", "surge", "loon", "quanx":
		return true
	default:
		return false
	}
}

func (s *server) loadProxies(sourceValue string) ([]map[string]any, error) {
	var all []map[string]any
	for _, part := range strings.Split(sourceValue, "|") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		text := part
		if strings.HasPrefix(part, "http://") || strings.HasPrefix(part, "https://") {
			fetched, err := s.fetchText(part)
			if err != nil {
				return nil, fmt.Errorf("source fetch failed")
			}
			text = fetched
		}

		proxies, err := parseProxySource(text)
		if err != nil {
			return nil, err
		}
		all = append(all, proxies...)
	}
	all = dedupeProxies(all)
	if len(all) == 0 {
		return nil, errors.New("source contains no supported proxy nodes")
	}
	return all, nil
}

func (s *server) fetchText(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", fmt.Errorf("invalid url")
	}

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("user-agent", defaultUserAgent)
	req.Header.Set("accept", "text/yaml, text/plain, application/json, */*")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("upstream status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxBodyBytes {
		return "", fmt.Errorf("upstream body too large")
	}
	return string(body), nil
}

func parseProxySource(text string) ([]map[string]any, error) {
	if proxies, ok := parseClashProxies(text); ok {
		return proxies, nil
	}
	return parseURIProxies(text)
}

func parseClashProxies(text string) ([]map[string]any, bool) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, false
	}
	rawProxies, ok := doc["proxies"].([]any)
	if !ok {
		return nil, false
	}

	var proxies []map[string]any
	for _, item := range rawProxies {
		proxy, ok := normalizeMap(item)
		if !ok {
			continue
		}
		if stringValue(proxy["name"]) == "" || stringValue(proxy["type"]) == "" {
			continue
		}
		proxies = append(proxies, proxy)
	}
	return proxies, len(proxies) > 0
}

func parseURIProxies(text string) ([]map[string]any, error) {
	var proxies []map[string]any
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		proxy, err := parseURIProxy(line, i+1)
		if err == nil && proxy != nil {
			proxies = append(proxies, proxy)
		}
	}
	if len(proxies) == 0 {
		return nil, errors.New("source contains no supported proxy nodes")
	}
	return proxies, nil
}

func parseURIProxy(line string, index int) (map[string]any, error) {
	if strings.HasPrefix(line, "vmess://") {
		return parseVmessURI(line, index)
	}
	u, err := url.Parse(line)
	if err != nil {
		return nil, err
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "trojan", "vless", "hysteria2", "hy2", "anytls":
	default:
		return nil, fmt.Errorf("unsupported uri scheme")
	}

	name := fragmentName(u, fmt.Sprintf("%s-%d", scheme, index))
	host := u.Hostname()
	port := parseInt(u.Port(), 0)
	if host == "" || port == 0 {
		return nil, fmt.Errorf("missing host or port")
	}

	query := u.Query()
	proxyType := scheme
	if proxyType == "hy2" {
		proxyType = "hysteria2"
	}
	proxy := map[string]any{
		"name":   name,
		"type":   proxyType,
		"server": host,
		"port":   port,
		"udp":    true,
	}

	switch proxyType {
	case "vless":
		proxy["uuid"] = u.User.Username()
		if flow := query.Get("flow"); flow != "" {
			proxy["flow"] = flow
		}
		if query.Get("security") == "tls" || query.Get("tls") == "1" {
			proxy["tls"] = true
		}
	default:
		if password := u.User.Username(); password != "" {
			proxy["password"] = password
		}
	}

	applyCommonQuery(proxy, query)
	return proxy, nil
}

func parseVmessURI(line string, index int) (map[string]any, error) {
	encoded := strings.TrimPrefix(line, "vmess://")
	data, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		data, err = base64.StdEncoding.DecodeString(encoded)
	}
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}

	host := stringValue(payload["add"])
	port := parseInt(fmt.Sprint(payload["port"]), 0)
	if host == "" || port == 0 {
		return nil, fmt.Errorf("invalid vmess node")
	}
	proxy := map[string]any{
		"name":    firstNonEmpty(stringValue(payload["ps"]), fmt.Sprintf("vmess-%d", index)),
		"type":    "vmess",
		"server":  host,
		"port":    port,
		"uuid":    stringValue(payload["id"]),
		"alterId": parseInt(fmt.Sprint(payload["aid"]), 0),
		"cipher":  firstNonEmpty(stringValue(payload["scy"]), "auto"),
		"udp":     true,
	}
	if netType := stringValue(payload["net"]); netType != "" && netType != "tcp" {
		proxy["network"] = netType
	}
	if tls := stringValue(payload["tls"]); tls == "tls" {
		proxy["tls"] = true
	}
	if sni := stringValue(payload["sni"]); sni != "" {
		proxy["servername"] = sni
	}
	return proxy, nil
}

func applyCommonQuery(proxy map[string]any, query url.Values) {
	if sni := firstNonEmpty(query.Get("sni"), query.Get("servername"), query.Get("peer")); sni != "" {
		proxy["sni"] = sni
		if proxy["type"] == "vless" {
			proxy["servername"] = sni
		}
	}
	if fp := firstNonEmpty(query.Get("fp"), query.Get("client-fingerprint")); fp != "" {
		proxy["client-fingerprint"] = fp
	}
	if alpn := query.Get("alpn"); alpn != "" {
		proxy["alpn"] = strings.Split(alpn, ",")
	}
	if insecure := firstNonEmpty(query.Get("allowInsecure"), query.Get("skip-cert-verify")); insecure != "" {
		proxy["skip-cert-verify"] = insecure == "1" || strings.EqualFold(insecure, "true")
	}
	if network := firstNonEmpty(query.Get("type"), query.Get("network")); network != "" && network != "tcp" {
		proxy["network"] = network
		if network == "ws" {
			ws := map[string]any{}
			if path := query.Get("path"); path != "" {
				ws["path"] = path
			}
			if host := query.Get("host"); host != "" {
				ws["headers"] = map[string]any{"Host": host}
			}
			if len(ws) > 0 {
				proxy["ws-opts"] = ws
			}
		}
	}
}

func parseTemplate(text string, names []string) parsedTemplate {
	result := parsedTemplate{
		RuleProviders: map[string]ruleProvider{},
	}
	providerByURL := map[string]string{}
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "custom_proxy_group="):
			group := parseProxyGroup(strings.TrimPrefix(line, "custom_proxy_group="), names)
			if len(group.Proxies) > 0 {
				result.Groups = append(result.Groups, group)
			}
		case strings.HasPrefix(line, "ruleset="):
			parseRulesetLine(strings.TrimPrefix(line, "ruleset="), &result, providerByURL)
		}
	}
	if len(result.Groups) == 0 {
		result.Groups = []proxyGroup{{
			Name: "Proxy", Type: "select", Proxies: append([]string{}, names...),
		}}
	}
	if !hasMatchRule(result.Rules) {
		result.Rules = append(result.Rules, "MATCH,"+result.Groups[0].Name)
	}
	return result
}

func parseProxyGroup(spec string, names []string) proxyGroup {
	parts := splitAndTrim(spec, "`")
	if len(parts) < 2 {
		return proxyGroup{}
	}
	group := proxyGroup{
		Name: parts[0],
		Type: parts[1],
	}
	for _, token := range parts[2:] {
		switch {
		case strings.HasPrefix(token, "[]"):
			group.Proxies = append(group.Proxies, strings.TrimPrefix(token, "[]"))
		case strings.HasPrefix(token, "http://") || strings.HasPrefix(token, "https://"):
			group.URL = token
		case numericCSV(token):
			values := strings.Split(token, ",")
			group.Interval = parseInt(values[0], 300)
			if len(values) >= 3 {
				group.Tolerance = parseInt(values[2], 100)
			} else if len(values) >= 2 {
				group.Tolerance = parseInt(values[1], 100)
			}
		default:
			group.Proxies = append(group.Proxies, matchNames(token, names)...)
		}
	}
	group.Proxies = uniqueStrings(group.Proxies)
	if group.URL == "" && (group.Type == "url-test" || group.Type == "fallback" || group.Type == "load-balance") {
		group.URL = defaultTestURL
	}
	if group.Interval == 0 && (group.Type == "url-test" || group.Type == "fallback" || group.Type == "load-balance") {
		group.Interval = 300
	}
	if len(group.Proxies) == 0 {
		group.Proxies = []string{"DIRECT"}
	}
	return group
}

func parseRulesetLine(spec string, result *parsedTemplate, providerByURL map[string]string) {
	policy, source, ok := strings.Cut(spec, ",")
	if !ok {
		return
	}
	policy = strings.TrimSpace(policy)
	source = strings.TrimSpace(source)
	if policy == "" || source == "" {
		return
	}
	if strings.HasPrefix(source, "[]") {
		if rule := inlineRule(policy, strings.TrimPrefix(source, "[]")); rule != "" {
			result.Rules = append(result.Rules, rule)
		}
		return
	}
	if source == "rules/LocalAreaNetwork.list" {
		result.Rules = append(result.Rules, lanRules...)
		return
	}
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		parts := splitAndTrim(source, ",")
		remote := parts[0]
		interval := 86400
		if len(parts) > 1 {
			interval = parseInt(parts[1], 86400)
		}
		name, exists := providerByURL[remote]
		if !exists {
			name = providerName(remote)
			providerByURL[remote] = name
			result.RuleProviders[name] = ruleProvider{
				Type: "http", Behavior: "classical", URL: remote,
				Path: "./ruleset/" + name + ".yaml", Interval: interval,
			}
		}
		result.Rules = append(result.Rules, "RULE-SET,"+name+","+policy)
	}
}

func inlineRule(policy, body string) string {
	parts := splitAndTrim(body, ",")
	if len(parts) == 0 {
		return ""
	}
	if strings.EqualFold(parts[0], "FINAL") {
		return "MATCH," + policy
	}
	noResolve := len(parts) > 0 && parts[len(parts)-1] == "no-resolve"
	if noResolve {
		parts = parts[:len(parts)-1]
	}
	parts = append(parts, policy)
	if noResolve {
		parts = append(parts, "no-resolve")
	}
	return strings.Join(parts, ",")
}

func buildConfig(proxies []map[string]any, parsed parsedTemplate) mihomoConfig {
	return mihomoConfig{
		MixedPort:               7890,
		AllowLAN:                false,
		Mode:                    "rule",
		LogLevel:                "info",
		IPv6:                    true,
		TCPConcurrent:           true,
		GlobalClientFingerprint: "chrome",
		Profile: profileConfig{
			StoreSelected: true,
			StoreFakeIP:   true,
		},
		DNS: dnsConfig{
			Enable:            true,
			IPv6:              true,
			EnhancedMode:      "fake-ip",
			FakeIPRange:       "198.18.0.1/16",
			DefaultNameserver: []string{"223.5.5.5", "223.6.6.6", "119.29.29.29"},
			Nameserver:        []string{"https://1.12.12.12/dns-query", "https://120.53.53.53/dns-query"},
			FakeIPFilter:      []string{"*.lan", "*.local", "*.bigscale-atria.ts.net", "*.tailscale.com", "*.tailscale.io"},
		},
		Proxies:       proxies,
		ProxyGroups:   parsed.Groups,
		RuleProviders: parsed.RuleProviders,
		Rules:         parsed.Rules,
	}
}

func normalizeTarget(target string) string {
	target = strings.ToLower(strings.TrimSpace(target))
	target = strings.Split(target, "&")[0]
	switch target {
	case "", "clash", "clashmeta", "mihomo", "openclash", "stash":
		return "mihomo"
	case "sing-box", "singbox":
		return "singbox"
	case "uri", "mixed", "v2ray", "shadowrocket", "passwall", "passwall2":
		return "uri"
	case "surge":
		return "surge"
	case "loon":
		return "loon"
	case "quanx", "qx", "quantumultx", "quantumult-x":
		return "quanx"
	default:
		return target
	}
}

func renderTarget(target string, proxies []map[string]any, parsed parsedTemplate) (renderResult, error) {
	switch normalizeTarget(target) {
	case "mihomo":
		body, err := yaml.Marshal(buildConfig(proxies, parsed))
		if err != nil {
			return renderResult{}, fmt.Errorf("yaml marshal failed")
		}
		return renderResult{Body: body, ContentType: "text/yaml; charset=utf-8", Extension: "yaml", Renderer: "subconverter-modern/mihomo"}, nil
	case "singbox":
		body, err := json.MarshalIndent(buildSingBoxConfig(proxies, parsed), "", "  ")
		if err != nil {
			return renderResult{}, fmt.Errorf("sing-box json marshal failed")
		}
		body = append(body, '\n')
		return renderResult{Body: body, ContentType: "application/json; charset=utf-8", Extension: "json", Renderer: "subconverter-modern/sing-box"}, nil
	case "uri":
		body := []byte(strings.Join(proxyURIs(proxies), "\n") + "\n")
		return renderResult{Body: body, ContentType: "text/plain; charset=utf-8", Extension: "txt", Renderer: "subconverter-modern/uri"}, nil
	case "surge":
		body := []byte(renderSurgeConfig(proxies, parsed))
		return renderResult{Body: body, ContentType: "text/plain; charset=utf-8", Extension: "conf", Renderer: "subconverter-modern/surge"}, nil
	case "loon":
		body := []byte(renderLoonConfig(proxies, parsed))
		return renderResult{Body: body, ContentType: "text/plain; charset=utf-8", Extension: "conf", Renderer: "subconverter-modern/loon"}, nil
	case "quanx":
		body := []byte(renderQuantumultXConfig(proxies))
		return renderResult{Body: body, ContentType: "text/plain; charset=utf-8", Extension: "conf", Renderer: "subconverter-modern/quanx"}, nil
	default:
		return renderResult{}, fmt.Errorf("unsupported target")
	}
}

func buildSingBoxConfig(proxies []map[string]any, parsed parsedTemplate) singBoxConfig {
	outbounds := []map[string]any{
		{"type": "direct", "tag": "DIRECT"},
		{"type": "block", "tag": "REJECT"},
	}
	for _, proxy := range proxies {
		if outbound := singBoxOutbound(proxy); outbound != nil {
			outbounds = append(outbounds, outbound)
		}
	}
	tags := outboundTags(outbounds)
	for _, group := range parsed.Groups {
		outbound := map[string]any{
			"type":      "selector",
			"tag":       group.Name,
			"outbounds": filterKnownTags(group.Proxies, tags),
		}
		if group.Type == "url-test" {
			outbound["type"] = "urltest"
			outbound["url"] = firstNonEmpty(group.URL, defaultTestURL)
			outbound["interval"] = durationSeconds(group.Interval, 300)
			if group.Tolerance > 0 {
				outbound["tolerance"] = group.Tolerance
			}
		}
		if len(outbound["outbounds"].([]string)) == 0 {
			outbound["outbounds"] = []string{"DIRECT"}
		}
		outbounds = append(outbounds, outbound)
		tags[group.Name] = true
	}

	routeRules, final := singBoxRules(parsed.Rules, tags)
	if final == "" && len(parsed.Groups) > 0 {
		final = parsed.Groups[0].Name
	}
	if final == "" {
		final = "DIRECT"
	}

	return singBoxConfig{
		Log: map[string]any{"level": "info"},
		DNS: map[string]any{
			"servers": []map[string]any{
				{"tag": "ali", "address": "https://223.5.5.5/dns-query", "detour": "DIRECT"},
				{"tag": "dnspod", "address": "https://120.53.53.53/dns-query", "detour": "DIRECT"},
			},
			"final": "ali",
		},
		Outbounds: outbounds,
		Route: map[string]any{
			"rules":                 routeRules,
			"final":                 final,
			"auto_detect_interface": true,
		},
		Experimental: map[string]any{
			"cache_file": map[string]any{"enabled": true},
		},
	}
}

func singBoxOutbound(proxy map[string]any) map[string]any {
	typ := strings.ToLower(stringValue(proxy["type"]))
	tag := stringValue(proxy["name"])
	server := stringValue(proxy["server"])
	port := intValue(proxy["port"], 0)
	if typ == "" || tag == "" || server == "" || port == 0 {
		return nil
	}
	out := map[string]any{
		"type":        typ,
		"tag":         tag,
		"server":      server,
		"server_port": port,
	}
	switch typ {
	case "trojan", "hysteria2", "anytls":
		if password := stringValue(proxy["password"]); password != "" {
			out["password"] = password
		}
		applySingBoxTLS(out, proxy, true)
	case "vless":
		out["uuid"] = stringValue(proxy["uuid"])
		if flow := stringValue(proxy["flow"]); flow != "" {
			out["flow"] = flow
		}
		applySingBoxTLS(out, proxy, boolValue(proxy["tls"]) || stringValue(proxy["servername"]) != "" || stringValue(proxy["sni"]) != "")
		applySingBoxTransport(out, proxy)
	case "vmess":
		out["uuid"] = stringValue(proxy["uuid"])
		out["security"] = firstNonEmpty(stringValue(proxy["cipher"]), "auto")
		if alterID := intValue(proxy["alterId"], -1); alterID >= 0 {
			out["alter_id"] = alterID
		}
		applySingBoxTLS(out, proxy, boolValue(proxy["tls"]) || stringValue(proxy["servername"]) != "" || stringValue(proxy["sni"]) != "")
		applySingBoxTransport(out, proxy)
	case "shadowsocks", "ss":
		out["type"] = "shadowsocks"
		out["method"] = stringValue(proxy["cipher"])
		out["password"] = stringValue(proxy["password"])
	default:
		return nil
	}
	return out
}

func applySingBoxTLS(out map[string]any, proxy map[string]any, enabled bool) {
	if !enabled {
		return
	}
	tls := map[string]any{"enabled": true}
	if sni := firstNonEmpty(stringValue(proxy["servername"]), stringValue(proxy["sni"])); sni != "" {
		tls["server_name"] = sni
	}
	if boolValue(proxy["skip-cert-verify"]) {
		tls["insecure"] = true
	}
	if fp := stringValue(proxy["client-fingerprint"]); fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	out["tls"] = tls
}

func applySingBoxTransport(out map[string]any, proxy map[string]any) {
	if stringValue(proxy["network"]) != "ws" {
		return
	}
	ws := map[string]any{"type": "ws"}
	if opts, ok := proxy["ws-opts"].(map[string]any); ok {
		if path := stringValue(opts["path"]); path != "" {
			ws["path"] = path
		}
		if headers, ok := opts["headers"].(map[string]any); ok && len(headers) > 0 {
			ws["headers"] = headers
		}
	}
	out["transport"] = ws
}

func singBoxRules(rules []string, tags map[string]bool) ([]map[string]any, string) {
	var out []map[string]any
	final := ""
	for _, rule := range rules {
		parts := splitAndTrim(rule, ",")
		if len(parts) < 2 {
			continue
		}
		kind := strings.ToUpper(parts[0])
		if kind == "MATCH" && len(parts) >= 2 {
			if tags[parts[1]] || parts[1] == "DIRECT" || parts[1] == "REJECT" {
				final = parts[1]
			}
			continue
		}
		if len(parts) < 3 {
			continue
		}
		policy := parts[len(parts)-1]
		if policy == "no-resolve" && len(parts) >= 4 {
			policy = parts[len(parts)-2]
		}
		if !tags[policy] && policy != "DIRECT" && policy != "REJECT" {
			continue
		}
		value := parts[1]
		r := map[string]any{"outbound": policy}
		switch kind {
		case "DOMAIN":
			r["domain"] = []string{value}
		case "DOMAIN-SUFFIX":
			r["domain_suffix"] = []string{value}
		case "DOMAIN-KEYWORD":
			r["domain_keyword"] = []string{value}
		case "IP-CIDR", "IP-CIDR6":
			r["ip_cidr"] = []string{value}
		case "GEOIP":
			r["geoip"] = []string{strings.ToLower(value)}
		default:
			continue
		}
		out = append(out, r)
	}
	return out, final
}

func renderSurgeConfig(proxies []map[string]any, parsed parsedTemplate) string {
	var b strings.Builder
	b.WriteString("# Generated by subconverter-modern for Surge\n[General]\nloglevel = notify\n\n[Proxy]\n")
	for _, proxy := range proxies {
		if line := surgeProxyLine(proxy); line != "" {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	b.WriteString("\n[Proxy Group]\n")
	for _, group := range parsed.Groups {
		b.WriteString(surgeGroupLine(group))
		b.WriteByte('\n')
	}
	b.WriteString("\n[Rule]\n")
	for _, rule := range surgeRules(parsed) {
		b.WriteString(rule)
		b.WriteByte('\n')
	}
	return b.String()
}

func renderLoonConfig(proxies []map[string]any, parsed parsedTemplate) string {
	var b strings.Builder
	b.WriteString("# Generated by subconverter-modern for Loon\n[General]\ninterface-mode = auto\nipv6 = true\n\n[Proxy]\n")
	for _, proxy := range proxies {
		if uri := proxyURI(proxy); uri != "" {
			b.WriteString(stringValue(proxy["name"]))
			b.WriteString(" = ")
			b.WriteString(uri)
			b.WriteByte('\n')
		}
	}
	b.WriteString("\n[Proxy Group]\n")
	for _, group := range parsed.Groups {
		b.WriteString(loonGroupLine(group))
		b.WriteByte('\n')
	}
	b.WriteString("\n[Rule]\n")
	for _, rule := range surgeRules(parsed) {
		b.WriteString(strings.ReplaceAll(rule, "FINAL,", "FINAL,"))
		b.WriteByte('\n')
	}
	return b.String()
}

func renderQuantumultXConfig(proxies []map[string]any) string {
	var b strings.Builder
	b.WriteString("# Generated by subconverter-modern for Quantumult X\n")
	b.WriteString("# This renderer emits URI-style local nodes for import compatibility.\n\n[server_local]\n")
	for _, proxy := range proxies {
		if uri := proxyURI(proxy); uri != "" {
			b.WriteString(uri)
			b.WriteByte('\n')
		}
	}
	b.WriteString("\n[policy]\nstatic=Proxy, server-tag-regex=.*, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Proxy.png\n\n[filter]\nfinal, Proxy\n")
	return b.String()
}

func proxyURIs(proxies []map[string]any) []string {
	var uris []string
	for _, proxy := range proxies {
		if uri := proxyURI(proxy); uri != "" {
			uris = append(uris, uri)
		}
	}
	return uris
}

func proxyURI(proxy map[string]any) string {
	typ := strings.ToLower(stringValue(proxy["type"]))
	name := stringValue(proxy["name"])
	server := stringValue(proxy["server"])
	port := intValue(proxy["port"], 0)
	if typ == "" || name == "" || server == "" || port == 0 {
		return ""
	}
	fragment := url.QueryEscape(name)
	query := url.Values{}
	addTLSQuery(query, proxy)
	switch typ {
	case "trojan":
		return fmt.Sprintf("trojan://%s@%s:%d?%s#%s", url.QueryEscape(stringValue(proxy["password"])), server, port, query.Encode(), fragment)
	case "vless":
		query.Set("encryption", "none")
		if boolValue(proxy["tls"]) || stringValue(proxy["servername"]) != "" || stringValue(proxy["sni"]) != "" {
			query.Set("security", "tls")
		}
		if flow := stringValue(proxy["flow"]); flow != "" {
			query.Set("flow", flow)
		}
		addNetworkQuery(query, proxy)
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s", url.QueryEscape(stringValue(proxy["uuid"])), server, port, query.Encode(), fragment)
	case "hysteria2", "hy2":
		return fmt.Sprintf("hysteria2://%s@%s:%d?%s#%s", url.QueryEscape(stringValue(proxy["password"])), server, port, query.Encode(), fragment)
	case "anytls":
		return fmt.Sprintf("anytls://%s@%s:%d?%s#%s", url.QueryEscape(stringValue(proxy["password"])), server, port, query.Encode(), fragment)
	case "vmess":
		payload := map[string]string{
			"v":    "2",
			"ps":   name,
			"add":  server,
			"port": strconv.Itoa(port),
			"id":   stringValue(proxy["uuid"]),
			"aid":  strconv.Itoa(intValue(proxy["alterId"], 0)),
			"net":  firstNonEmpty(stringValue(proxy["network"]), "tcp"),
			"type": "none",
			"host": wsHost(proxy),
			"path": wsPath(proxy),
			"tls":  vmessTLS(proxy),
			"scy":  firstNonEmpty(stringValue(proxy["cipher"]), "auto"),
		}
		data, _ := json.Marshal(payload)
		return "vmess://" + base64.StdEncoding.EncodeToString(data)
	case "shadowsocks", "ss":
		user := base64.RawURLEncoding.EncodeToString([]byte(stringValue(proxy["cipher"]) + ":" + stringValue(proxy["password"])))
		return fmt.Sprintf("ss://%s@%s:%d#%s", user, server, port, fragment)
	default:
		return ""
	}
}

func addTLSQuery(query url.Values, proxy map[string]any) {
	if sni := firstNonEmpty(stringValue(proxy["servername"]), stringValue(proxy["sni"])); sni != "" {
		query.Set("sni", sni)
	}
	if boolValue(proxy["skip-cert-verify"]) {
		query.Set("allowInsecure", "1")
	}
	if fp := stringValue(proxy["client-fingerprint"]); fp != "" {
		query.Set("fp", fp)
	}
	if alpn, ok := proxy["alpn"].([]any); ok {
		var values []string
		for _, item := range alpn {
			values = append(values, fmt.Sprint(item))
		}
		query.Set("alpn", strings.Join(values, ","))
	}
}

func addNetworkQuery(query url.Values, proxy map[string]any) {
	network := stringValue(proxy["network"])
	if network == "" || network == "tcp" {
		return
	}
	query.Set("type", network)
	if network == "ws" {
		if path := wsPath(proxy); path != "" {
			query.Set("path", path)
		}
		if host := wsHost(proxy); host != "" {
			query.Set("host", host)
		}
	}
}

func surgeProxyLine(proxy map[string]any) string {
	name := stringValue(proxy["name"])
	typ := strings.ToLower(stringValue(proxy["type"]))
	server := stringValue(proxy["server"])
	port := intValue(proxy["port"], 0)
	if name == "" || server == "" || port == 0 {
		return ""
	}
	switch typ {
	case "trojan":
		return fmt.Sprintf("%s = trojan, %s, %d, password=%s, tls=true, sni=%s, skip-cert-verify=%t, udp-relay=true", name, server, port, stringValue(proxy["password"]), firstNonEmpty(stringValue(proxy["sni"]), stringValue(proxy["servername"])), boolValue(proxy["skip-cert-verify"]))
	case "anytls":
		return fmt.Sprintf("%s = anytls, %s, %d, password=%s, sni=%s, skip-cert-verify=%t, udp-relay=true", name, server, port, stringValue(proxy["password"]), firstNonEmpty(stringValue(proxy["sni"]), stringValue(proxy["servername"])), boolValue(proxy["skip-cert-verify"]))
	case "hysteria2", "hy2":
		return fmt.Sprintf("%s = hysteria2, %s, %d, password=%s, sni=%s, skip-cert-verify=%t", name, server, port, stringValue(proxy["password"]), firstNonEmpty(stringValue(proxy["sni"]), stringValue(proxy["servername"])), boolValue(proxy["skip-cert-verify"]))
	case "snell":
		return fmt.Sprintf("%s = snell, %s, %d, psk=%s, version=%d", name, server, port, stringValue(proxy["psk"]), intValue(proxy["version"], 5))
	default:
		return ""
	}
}

func surgeGroupLine(group proxyGroup) string {
	parts := append([]string{group.Name + " = " + surgeGroupType(group.Type)}, group.Proxies...)
	if group.URL != "" && (group.Type == "url-test" || group.Type == "fallback") {
		parts = append(parts, "url="+group.URL)
	}
	if group.Interval > 0 && (group.Type == "url-test" || group.Type == "fallback") {
		parts = append(parts, "interval="+strconv.Itoa(group.Interval))
	}
	return strings.Join(parts, ", ")
}

func loonGroupLine(group proxyGroup) string {
	parts := append([]string{group.Name + " = " + surgeGroupType(group.Type)}, group.Proxies...)
	if group.URL != "" && (group.Type == "url-test" || group.Type == "fallback") {
		parts = append(parts, "url = "+group.URL)
	}
	if group.Interval > 0 && (group.Type == "url-test" || group.Type == "fallback") {
		parts = append(parts, "interval = "+strconv.Itoa(group.Interval))
	}
	return strings.Join(parts, ",")
}

func surgeGroupType(value string) string {
	switch value {
	case "url-test":
		return "url-test"
	case "fallback":
		return "fallback"
	default:
		return "select"
	}
}

func surgeRules(parsed parsedTemplate) []string {
	var out []string
	providerURL := map[string]string{}
	for name, provider := range parsed.RuleProviders {
		providerURL[name] = provider.URL
	}
	for _, rule := range parsed.Rules {
		parts := splitAndTrim(rule, ",")
		if len(parts) == 0 {
			continue
		}
		if parts[0] == "MATCH" && len(parts) >= 2 {
			out = append(out, "FINAL,"+parts[1])
			continue
		}
		if parts[0] == "RULE-SET" && len(parts) >= 3 {
			if remote := providerURL[parts[1]]; remote != "" {
				out = append(out, "RULE-SET,"+remote+","+parts[2])
			}
			continue
		}
		out = append(out, rule)
	}
	return out
}

func outboundTags(outbounds []map[string]any) map[string]bool {
	tags := map[string]bool{}
	for _, outbound := range outbounds {
		if tag := stringValue(outbound["tag"]); tag != "" {
			tags[tag] = true
		}
	}
	return tags
}

func filterKnownTags(values []string, tags map[string]bool) []string {
	var out []string
	for _, value := range values {
		if tags[value] || value == "DIRECT" || value == "REJECT" {
			out = append(out, value)
		}
	}
	return uniqueStrings(out)
}

func durationSeconds(value, fallback int) string {
	if value <= 0 {
		value = fallback
	}
	return strconv.Itoa(value) + "s"
}

func wsPath(proxy map[string]any) string {
	if opts, ok := proxy["ws-opts"].(map[string]any); ok {
		return stringValue(opts["path"])
	}
	return ""
}

func wsHost(proxy map[string]any) string {
	if opts, ok := proxy["ws-opts"].(map[string]any); ok {
		if headers, ok := opts["headers"].(map[string]any); ok {
			return stringValue(headers["Host"])
		}
	}
	return ""
}

func vmessTLS(proxy map[string]any) string {
	if boolValue(proxy["tls"]) || stringValue(proxy["servername"]) != "" || stringValue(proxy["sni"]) != "" {
		return "tls"
	}
	return ""
}

func normalizeMap(item any) (map[string]any, bool) {
	switch value := item.(type) {
	case map[string]any:
		return value, true
	case map[any]any:
		out := map[string]any{}
		for k, v := range value {
			out[fmt.Sprint(k)] = v
		}
		return out, true
	default:
		return nil, false
	}
}

func proxyNames(proxies []map[string]any) []string {
	names := make([]string, 0, len(proxies))
	for _, proxy := range proxies {
		if name := stringValue(proxy["name"]); name != "" {
			names = append(names, name)
		}
	}
	return names
}

func dedupeProxies(proxies []map[string]any) []map[string]any {
	seen := map[string]int{}
	var out []map[string]any
	for _, proxy := range proxies {
		name := stringValue(proxy["name"])
		if name == "" {
			continue
		}
		seen[name]++
		if seen[name] > 1 {
			name = fmt.Sprintf("%s %d", name, seen[name])
			proxy["name"] = name
		}
		out = append(out, proxy)
	}
	return out
}

func matchNames(pattern string, names []string) []string {
	if pattern == ".*" {
		return append([]string{}, names...)
	}
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return nil
	}
	var matched []string
	for _, name := range names {
		if re.MatchString(name) {
			matched = append(matched, name)
		}
	}
	return matched
}

func providerName(remote string) string {
	parsed, err := url.Parse(remote)
	base := "ruleset"
	if err == nil {
		tail := "ruleset"
		parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		if len(parts) > 0 && parts[len(parts)-1] != "" {
			tail = parts[len(parts)-1]
		}
		base = parsed.Hostname() + "-" + tail
	}
	hash := sha1.Sum([]byte(remote))
	return slug(base) + "-" + hex.EncodeToString(hash[:])[:8]
}

func slug(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	result := strings.Trim(b.String(), "-")
	if result == "" {
		return "ruleset"
	}
	if len(result) > 72 {
		return result[:72]
	}
	return result
}

func fragmentName(u *url.URL, fallback string) string {
	if u.Fragment == "" {
		return fallback
	}
	name, err := url.QueryUnescape(u.Fragment)
	if err != nil || name == "" {
		return fallback
	}
	return name
}

func splitAndTrim(value, sep string) []string {
	raw := strings.Split(value, sep)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func hasMatchRule(rules []string) bool {
	for _, rule := range rules {
		if strings.HasPrefix(rule, "MATCH,") {
			return true
		}
	}
	return false
}

func numericCSV(value string) bool {
	for _, item := range strings.Split(value, ",") {
		if item == "" {
			return false
		}
		if _, err := strconv.Atoi(item); err != nil {
			return false
		}
	}
	return true
}

func parseInt(value string, fallback int) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return parsed
}

func intValue(value any, fallback int) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case int32:
		return int(v)
	case float64:
		return int(v)
	case float32:
		return int(v)
	case uint64:
		return int(v)
	case uint:
		return int(v)
	case string:
		return parseInt(v, fallback)
	default:
		text := strings.TrimSpace(fmt.Sprint(value))
		if text == "" || text == "<nil>" {
			return fallback
		}
		return parseInt(text, fallback)
	}
}

func boolValue(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	default:
		return false
	}
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func safeFilename(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "SubConverterModern"
	}
	replacer := strings.NewReplacer("/", "-", "\\", "-", "\"", "", "\n", "", "\r", "")
	return replacer.Replace(value)
}

func writeJSON(w http.ResponseWriter, status int, data map[string]any) {
	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"ok":    false,
		"error": message,
	})
}

func init() {
	sort.Strings(lanRules)
}
