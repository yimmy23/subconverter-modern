package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestDNSSyncFromSurgeStyleTemplate(t *testing.T) {
	template := `
[custom]
[General]
dns-server = 223.5.5.5, 119.29.29.29
encrypted-dns-server = https://doh.pub/dns-query, https://dns.alidns.com/dns-query
always-real-ip = *.direct, *.lan
skip-proxy = localhost, *.local, 192.168.0.0/16
hijack-dns = 8.8.8.8:53

[Host]
*.taobao.com = server:223.5.5.5
router.local = server:system
nas.local = 192.168.31.41
mtalk.google.com = 108.177.125.188

custom_proxy_group=Proxy` + "`select`.*" + `
ruleset=Proxy,[]DOMAIN-SUFFIX,example.com
ruleset=DIRECT,[]GEOIP,CN,no-resolve
ruleset=Proxy,https://example.com/rules.list,86400
ruleset=Proxy,[]FINAL
`
	proxies := []map[string]any{{
		"name": "Test Node", "type": "vless", "server": "node.example.com", "port": 443,
		"uuid": "00000000-0000-0000-0000-000000000000", "tls": true,
	}}
	parsed := parseTemplate(template, []string{"Test Node"})

	mihomo := buildConfig(proxies, parsed)
	if got := mihomo.DNS.DefaultNameserver; len(got) != 2 || got[0] != "223.5.5.5" {
		t.Fatalf("unexpected mihomo default nameservers: %#v", got)
	}
	if got := mihomo.DNS.Nameserver; len(got) != 2 || got[0] != "https://doh.pub/dns-query" {
		t.Fatalf("unexpected mihomo encrypted nameservers: %#v", got)
	}
	if got := mihomo.DNS.NameserverPolicy["*.taobao.com"]; got != "223.5.5.5" {
		t.Fatalf("unexpected mihomo nameserver policy: %q", got)
	}
	if got := mihomo.Hosts["nas.local"]; got != "192.168.31.41" {
		t.Fatalf("unexpected mihomo host entry: %#v", got)
	}
	if !containsString(mihomo.DNS.FakeIPFilter, "*.direct") || !containsString(mihomo.DNS.FakeIPFilter, "nas.local") {
		t.Fatalf("mihomo fake-ip-filter did not include DNS bypass hosts: %#v", mihomo.DNS.FakeIPFilter)
	}

	singBox := buildSingBoxConfig(proxies, parsed, "https://sub.example.com")
	if got := stringValue(singBox.DNS["final"]); got == "" || got == "hosts" {
		t.Fatalf("unexpected sing-box DNS final: %q", got)
	}
	if !singBoxHasDNSServer(singBox.DNS, "hosts") || !singBoxHasDNSServer(singBox.DNS, "dns-1") {
		t.Fatalf("sing-box DNS servers missing hosts or upstream: %#v", singBox.DNS["servers"])
	}
	if !singBoxDNSServerHasField(singBox.DNS, "dns-1", "domain_resolver", "direct-dns-1") {
		t.Fatalf("sing-box DoH server did not include a domain resolver: %#v", singBox.DNS["servers"])
	}
	if stringValue(singBox.Route["default_domain_resolver"]) != "direct-dns-1" {
		t.Fatalf("sing-box route did not include a default domain resolver: %#v", singBox.Route)
	}
	singBoxBytes, err := json.Marshal(singBox)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(singBoxBytes), "preferred_by") || strings.Contains(string(singBoxBytes), "prefferedby") {
		t.Fatalf("sing-box output contains version-sensitive preferred_by field: %s", singBoxBytes)
	}
	if strings.Contains(string(singBoxBytes), `"geoip":`) || strings.Contains(string(singBoxBytes), `"geosite":`) {
		t.Fatalf("sing-box output contains removed geo database fields: %s", singBoxBytes)
	}
	if strings.Contains(string(singBoxBytes), `"fakeip":`) {
		t.Fatalf("sing-box output contains removed legacy fakeip field: %s", singBoxBytes)
	}
	if !singBoxHasRouteRuleSet(singBox.Route, "geoip-cn", "DIRECT") {
		t.Fatalf("sing-box output did not convert GEOIP to rule_set route: %#v", singBox.Route["rules"])
	}
	if !singBoxHasRemoteRuleSet(singBox.Route, "geoip-cn", "binary") {
		t.Fatalf("sing-box output did not include geoip-cn binary rule-set: %#v", singBox.Route["rule_set"])
	}
	if !strings.Contains(string(singBoxBytes), `"server":"hosts"`) {
		t.Fatalf("sing-box output did not route host entries to hosts server: %s", singBoxBytes)
	}
	if !strings.Contains(renderSurgeConfig(proxies, parsed), "encrypted-dns-server = https://doh.pub/dns-query") {
		t.Fatal("surge output did not include encrypted DNS settings")
	}
	loon := renderLoonConfig(proxies, parsed)
	if !strings.Contains(loon, "[Host]") || !strings.Contains(loon, "nas.local = 192.168.31.41") {
		t.Fatal("loon output did not include host mappings")
	}
	if !strings.Contains(loon, "dns-server = 223.5.5.5, 119.29.29.29") || !strings.Contains(loon, "doh-server = https://doh.pub/dns-query") {
		t.Fatal("loon output did not include DNS settings")
	}
	if !strings.Contains(renderQuantumultXConfig(proxies, parsed), "[dns]\ndoh-server = https://doh.pub/dns-query") {
		t.Fatal("quantumult x output did not include DoH settings")
	}
	if len(parsed.Rules) == 0 || len(parsed.RuleProviders) == 0 {
		t.Fatalf("template directives after [Host] were not parsed: rules=%d providers=%d", len(parsed.Rules), len(parsed.RuleProviders))
	}
}

func TestMihomoFiltersUnsupportedSnellVersions(t *testing.T) {
	proxies := []map[string]any{
		{"name": "Snell V3", "type": "snell", "server": "v3.example.com", "port": 443, "psk": "secret", "version": 3},
		{"name": "Snell V5", "type": "snell", "server": "v5.example.com", "port": 443, "psk": "secret", "version": 5},
		{"name": "Trojan", "type": "trojan", "server": "trojan.example.com", "port": 443, "password": "secret"},
	}
	filtered := filterProxiesForTarget("clash", proxies)
	if len(filtered) != 2 {
		t.Fatalf("unexpected filtered proxy count: %d", len(filtered))
	}
	for _, proxy := range filtered {
		if stringValue(proxy["name"]) == "Snell V5" {
			t.Fatal("mihomo target kept unsupported snell v5 proxy")
		}
	}
	parsed := parseTemplate("custom_proxy_group=Proxy`select`.*\nruleset=Proxy,[]FINAL\n", proxyNames(filtered))
	config := buildConfig(filtered, parsed)
	if containsString(config.ProxyGroups[0].Proxies, "Snell V5") {
		t.Fatal("proxy group referenced filtered snell v5 proxy")
	}
}

func TestV2rayNGTargetReturnsBase64URIList(t *testing.T) {
	proxies := []map[string]any{{
		"name": "Trojan", "type": "trojan", "server": "trojan.example.com", "port": 443,
		"password": "secret", "sni": "example.com",
	}}
	result, err := renderTarget("v2rayng", proxies, parsedTemplate{}, "")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(result.Body)))
	if err != nil {
		t.Fatalf("v2rayng output is not base64: %v", err)
	}
	if !strings.Contains(string(decoded), "trojan://") {
		t.Fatalf("decoded v2rayng output did not contain URI list: %s", decoded)
	}
	if result.Renderer != "subconverter-modern/v2rayng" {
		t.Fatalf("unexpected renderer: %s", result.Renderer)
	}
}

func TestSurfboardTargetUsesNativeDocumentedSyntax(t *testing.T) {
	allProxies := []map[string]any{
		{"name": "Trojan", "type": "trojan", "server": "trojan.example.com", "port": 443, "password": "trojan-secret", "sni": "tls.example.com", "skip-cert-verify": true},
		{"name": "AnyTLS", "type": "anytls", "server": "anytls.example.com", "port": 443, "password": "anytls-secret", "sni": "tls.example.com", "skip-cert-verify": true},
		{"name": "Hysteria2", "type": "hysteria2", "server": "hy2.example.com", "port": 443, "password": "hy2-secret", "sni": "tls.example.com", "skip-cert-verify": true},
		{"name": "Snell", "type": "snell", "server": "snell.example.com", "port": 443, "psk": "snell-secret", "version": 5},
		{"name": "Unsupported VLESS", "type": "vless", "server": "vless.example.com", "port": 443, "uuid": "00000000-0000-0000-0000-000000000000"},
	}
	if !isSupportedTarget("surfboard") || normalizeTarget("surfboard") != "surfboard" {
		t.Fatal("surfboard target is not registered")
	}
	proxies := filterProxiesForTarget("surfboard", allProxies)
	if len(proxies) != 4 {
		t.Fatalf("unexpected Surfboard proxy count: %d", len(proxies))
	}
	template := `
[General]
dns-server = 223.5.5.5, 119.29.29.29
doh-server = https://doh.pub/dns-query, https://dns.alidns.com/dns-query
always-real-ip = *.direct, *.lan
skip-proxy = localhost, *.local

[custom]
custom_proxy_group=Proxy` + "`select`.*" + `
custom_proxy_group=Auto` + "`url-test`.*`http://www.gstatic.com/generate_204`300,5,100" + `
ruleset=Proxy,[]FINAL
`
	parsed := parseTemplate(template, proxyNames(proxies))
	result, err := renderTarget("surfboard", proxies, parsed, "")
	if err != nil {
		t.Fatal(err)
	}
	body := string(result.Body)
	if result.Renderer != "subconverter-modern/surfboard" {
		t.Fatalf("unexpected renderer: %s", result.Renderer)
	}
	if surge := renderSurgeConfig(proxies, parsed); !strings.Contains(surge, "encrypted-dns-server = https://doh.pub/dns-query") {
		t.Fatalf("Surge output did not translate the documented doh-server input: %s", surge)
	}
	for _, want := range []string{
		"# Generated by subconverter-modern for Surfboard",
		"ipv6 = false",
		"dns-server = 223.5.5.5, 119.29.29.29",
		"doh-server = https://doh.pub/dns-query, https://dns.alidns.com/dns-query",
		"proxy-test-url = http://www.gstatic.com/generate_204",
		"test-timeout = 5",
		"Trojan = trojan, trojan.example.com, 443, password=trojan-secret, sni=tls.example.com, skip-cert-verify=true, udp-relay=true",
		"AnyTLS = anytls, anytls.example.com, 443, anytls-secret, skip-cert-verify=true, sni=tls.example.com, udp-relay=true",
		"Hysteria2 = hysteria2, hy2.example.com, 443, password=hy2-secret, skip-cert-verify=true, sni=tls.example.com, udp-relay=true",
		"Snell = snell, snell.example.com, 443, psk=snell-secret, version=4, udp-relay=true",
		"Auto = url-test, Trojan, AnyTLS, Hysteria2, Snell, url=http://www.gstatic.com/generate_204, interval=300, timeout=5, tolerance=100",
		"FINAL,Proxy",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Surfboard output missing %q:\n%s", want, body)
		}
	}
	for _, unwanted := range []string{"encrypted-dns-server", "Unsupported VLESS", "tls=true", "tfo=true"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("Surfboard output contains unsupported or unwanted token %q:\n%s", unwanted, body)
		}
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func singBoxHasRouteRuleSet(route map[string]any, tag, outbound string) bool {
	rules, ok := route["rules"].([]map[string]any)
	if !ok {
		return false
	}
	for _, rule := range rules {
		if stringValue(rule["outbound"]) == outbound && containsString(anyStringSlice(rule["rule_set"]), tag) {
			return true
		}
	}
	return false
}

func singBoxHasRemoteRuleSet(route map[string]any, tag, format string) bool {
	ruleSets, ok := route["rule_set"].([]map[string]any)
	if !ok {
		return false
	}
	for _, ruleSet := range ruleSets {
		if stringValue(ruleSet["tag"]) == tag && stringValue(ruleSet["type"]) == "remote" && stringValue(ruleSet["format"]) == format {
			return true
		}
	}
	return false
}

func singBoxHasDNSServer(dns map[string]any, tag string) bool {
	servers, ok := dns["servers"].([]map[string]any)
	if !ok {
		return false
	}
	for _, server := range servers {
		if stringValue(server["tag"]) == tag {
			return true
		}
	}
	return false
}

func singBoxDNSServerHasField(dns map[string]any, tag, field, value string) bool {
	servers, ok := dns["servers"].([]map[string]any)
	if !ok {
		return false
	}
	for _, server := range servers {
		if stringValue(server["tag"]) == tag && stringValue(server[field]) == value {
			return true
		}
	}
	return false
}
