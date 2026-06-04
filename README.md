# SubConverter Modern

SubConverter Modern is a small self-hosted subscription converter written in Go.
It converts Clash/Mihomo proxy sources or common proxy URI links into client-ready
configuration formats.

It is intentionally narrower than the original SubConverter project:

- preserve modern Clash/Mihomo proxy fields instead of re-parsing everything
- support modern node types such as AnyTLS and Hysteria2 when source data already
  contains compatible fields
- generate rule-based Mihomo YAML from a simple external template
- sync common Surge-style DNS settings from `[General]` and `[Host]` into
  Mihomo, sing-box, Surge, Loon, and Quantumult X outputs
- expose a compact HTTP API that is easy to run behind a reverse proxy or tunnel

## Supported Targets

| Target aliases | Output |
| --- | --- |
| `clash`, `clashmeta`, `mihomo`, `stash`, `openclash` | Full Mihomo YAML |
| `sing-box`, `singbox` | sing-box JSON |
| `surge` | Basic Surge configuration |
| `loon` | Basic Loon configuration |
| `quanx`, `qx`, `quantumultx`, `quantumult-x` | Basic Quantumult X configuration |
| `v2ray`, `v2rayng` | Base64-encoded URI node list for v2rayNG-style subscriptions |
| `uri`, `mixed`, `shadowrocket`, `passwall`, `passwall2` | Plain URI node list |

## Current Limitations

- This is not a complete drop-in replacement for every legacy SubConverter
  feature.
- sing-box output converts outbounds, selectors, inline rules, and remote
  `ruleset=` entries. Remote list URLs are exposed as native sing-box
  `route.rule_set` entries that point back to `/ruleset?url=...`, where this
  service converts Surge/Clash-style rule lists into sing-box source rule-set
  JSON. Surge-style `GEOIP,CN` rules are converted to sing-box `rule_set`
  matches backed by SagerNet's `geoip-cn.srs` binary rule-set, because native
  `geoip`/`geosite` route fields were removed in sing-box 1.12.
- Surge, Loon, and Quantumult X output can pass through advanced sections when
  they already exist in the external template. It does not infer or translate
  script/MITM/rewrite semantics across different client ecosystems.
- DNS conversion covers common resolver, encrypted resolver, fake-IP bypass,
  host mapping, and per-domain resolver settings. It is not a full semantic
  clone of every client-specific DNS option.
- sing-box output avoids legacy `dns.fakeip` because that field was removed in
  sing-box 1.14.
- sing-box encrypted DNS servers with domain hostnames are given an explicit
  `domain_resolver`, which is required by newer sing-box cores.
- sing-box route output sets `default_domain_resolver` so outbound server
  hostnames do not rely on deprecated implicit DNS resolution.
- Mihomo/Clash targets drop Snell nodes with unsupported versions. Mihomo only
  supports Snell v1-v3, so v5 nodes are intentionally excluded instead of being
  rewritten into a broken lower-version node.
- URI-style output depends on protocol URI support. Some protocols may be better
  represented in Mihomo YAML than in URI form.

## Safety Notes

- Treat subscription URLs and generated configs as secrets. They often contain
  node credentials.
- Do not publish private source URLs, tokens, or generated node lists.
- The server fetches source and template URLs supplied by the request. Run it in
  an environment that fits your trust model.
- This tool does not bypass provider restrictions or client/User-Agent policies.
  It only converts data that you are authorized to fetch.

## Quick Start

```bash
git clone https://github.com/yimmy23/subconverter-modern.git
cd subconverter-modern
go run .
```

The service listens on `:25500` by default.

```bash
curl http://127.0.0.1:25500/version
```

## Docker

```bash
docker build -t subconverter-modern .
docker run --rm -p 25500:25500 subconverter-modern
```

Use `LISTEN_ADDR` to change the bind address:

```bash
docker run --rm -p 127.0.0.1:25500:25500 \
  -e LISTEN_ADDR=:25500 \
  subconverter-modern
```

Use `DEFAULT_CONFIG_URL` to provide a default external template:

```bash
docker run --rm -p 127.0.0.1:25500:25500 \
  -e DEFAULT_CONFIG_URL=https://example.com/template.ini \
  subconverter-modern
```

## API

### `GET /version`

Returns the service version.

### `GET /health`

Returns a JSON health object.

### `GET /sub`

Converts a source subscription or node list.

Parameters:

| Name | Required | Description |
| --- | --- | --- |
| `target` | No | Output target. Defaults to `clash`. |
| `url` | Yes | Source URL or inline source value. Multiple sources can be joined with `\|`. |
| `config` | No | External template URL. If omitted, `DEFAULT_CONFIG_URL` is used. |
| `filename` | No | Download filename. Defaults to `SubConverterModern`. |

Example:

```bash
curl -G http://127.0.0.1:25500/sub \
  --data-urlencode "target=clash" \
  --data-urlencode "url=https://example.com/subscription.yaml" \
  --data-urlencode "config=https://example.com/template.ini" \
  --data-urlencode "filename=Profile" \
  -o Profile.yaml
```

sing-box:

```bash
curl -G http://127.0.0.1:25500/sub \
  --data-urlencode "target=sing-box" \
  --data-urlencode "url=https://example.com/subscription.yaml" \
  --data-urlencode "config=https://example.com/template.ini" \
  -o Profile.json
```

URI list:

```bash
curl -G http://127.0.0.1:25500/sub \
  --data-urlencode "target=uri" \
  --data-urlencode "url=https://example.com/subscription.yaml" \
  -o nodes.txt
```

v2rayNG subscription:

```bash
curl -G http://127.0.0.1:25500/sub \
  --data-urlencode "target=v2rayng" \
  --data-urlencode "url=https://example.com/subscription.yaml" \
  -o v2rayng.txt
```

`target=v2rayng` returns the URI list wrapped in Base64, matching common
v2rayNG subscription expectations. Use `target=uri` when you need a plain text
URI list.

When `target=sing-box`, remote `ruleset=` entries become native sing-box
`route.rule_set` records. Set `PUBLIC_BASE_URL` when the service is behind a
reverse proxy so generated rule-set URLs are externally reachable:

```bash
PUBLIC_BASE_URL=https://sub.example.com subconverter-modern
```

### `GET /ruleset`

Converts a remote Surge/Clash-style rule list into sing-box source rule-set JSON.

Parameters:

| Name | Required | Description |
| --- | --- | --- |
| `url` | Yes | Remote rule list URL. |

Example:

```bash
curl -G http://127.0.0.1:25500/ruleset \
  --data-urlencode "url=https://example.com/rules.list" \
  -o rules.json
```

The output follows sing-box source rule-set shape:

```json
{
  "version": 3,
  "rules": []
}
```

## Template Syntax

The optional external template uses a small subset of classic SubConverter-style
syntax.

Proxy groups:

```ini
custom_proxy_group=Proxy`select`[]AUTO`[]DIRECT`.*
custom_proxy_group=AUTO`url-test`.*`http://www.gstatic.com/generate_204`300,5,100
```

Inline rules:

```ini
ruleset=DIRECT,[]DOMAIN,localhost
ruleset=Proxy,[]DOMAIN-SUFFIX,example.com
ruleset=Proxy,[]FINAL
```

Remote rule providers for Mihomo:

```ini
ruleset=Proxy,https://example.com/rules.yaml,86400
```

DNS settings:

```ini
[General]
dns-server = 223.5.5.5, 119.29.29.29
encrypted-dns-server = https://doh.pub/dns-query, https://dns.alidns.com/dns-query
always-real-ip = *.lan, *.direct
skip-proxy = localhost, *.local, 192.168.0.0/16
hijack-dns = 8.8.8.8:53

[Host]
*.example.cn = server:223.5.5.5
router.local = server:system
nas.local = 192.168.1.10
```

DNS rendering by target:

- Mihomo: emits `dns`, `hosts`, `fake-ip-filter`, `nameserver-policy`,
  `proxy-server-nameserver`, and `direct-nameserver`.
- sing-box: emits `dns.servers`, `dns.rules`, `fakeip`, and host/predefined
  resolution rules. Host rules avoid `preferred_by` for compatibility with
  older sing-box Android clients.
- Surge and Loon: preserve `[General]` DNS lines and `[Host]` lines when
  applicable.
- Quantumult X: maps common DNS settings into `[dns]` records.

Advanced client-specific sections can be passed through if they already exist
in the template:

```ini
[URL Rewrite]
^http://old.example.com https://new.example.com 302

[Script]
job = type=cron,cronexp="* * * * *",script-path=https://example.com/job.js

[MITM]
hostname = example.com

[rewrite_local]
^https://qx.example.com url reject
```

Supported passthrough sections:

- Surge: `[URL Rewrite]`, `[Header Rewrite]`, `[Body Rewrite]`, `[Map Local]`,
  `[Map Remote]`, `[Script]`, `[Host]`, `[MITM]`
- Loon: `[Rewrite]`, `[URL Rewrite]`, `[Remote Rewrite]`, `[Script]`,
  `[Remote Script]`, `[Plugin]`, `[Host]`, `[MITM]`
- Quantumult X: `[rewrite_local]`, `[rewrite_remote]`, `[task_local]`,
  `[task_remote]`, `[mitm]`

See [examples/example.ini](examples/example.ini).

## Source Formats

Supported source forms:

- Clash/Mihomo YAML with a `proxies:` array
- URI lines for `trojan`, `vless`, `hysteria2`/`hy2`, `anytls`, and `vmess`

## Compatibility Endpoints

These endpoints return `OK` for compatibility with older maintenance scripts:

- `/refreshrules`
- `/updateconf`

`/readconf` returns a short text message because this server does not expose a
mutable runtime config.

## Development

```bash
go test ./...
go build -trimpath -ldflags="-s -w" .
```

## License

MIT
