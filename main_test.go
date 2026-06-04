package main

import (
	"encoding/base64"
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

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
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
