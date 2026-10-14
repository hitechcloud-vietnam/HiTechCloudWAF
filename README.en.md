Tiếng Việt: [README.md](README.md)

<p align="center">
  <img src="/images/logo.svg" width="360" alt="HiTechCloud WAF" />
</p>

<h4 align="center">HiTechCloud WAF — protect your web applications</h4>

HiTechCloud WAF is a self-hosted **WAF (Web Application Firewall) / reverse
proxy** that protects your web apps from attacks and exploits, with built-in
**multi-node clustering** and **health-checked DNS** in one platform.
Developed by Pho Tue SoftWare Solutions JSC / HiTechCloud-VN.

## Features

**HiTechCloud WAF Engine** (`waf/`, open source, standalone): reverse proxy +
OWASP Coraza + Core Rule Set v4, see [docs/en/engine.md](docs/en/engine.md).

Available in the HiTechCloud engine:

- Blocks web attacks with the OWASP CRS: SQL injection, XSS, RCE/command
  injection, LFI/RFI, path traversal, protocol attacks, scanners… (tested in
  both the query string and JSON/form bodies).
- Block / monitor / off modes, paranoia 1–4, per-site disabling of rules that
  cause false positives.
- Per-IP rate limiting (against brute force and HTTP floods) and path rules
  (a separate limit for `/login`, partner whitelists, skipping the WAF,
  blocking paths).
- Attack alerts via Telegram and webhooks (HMAC-signed).
- IP allow/deny ACLs (CIDR), country allow/deny (GeoIP).
- TLS with multiple certificates selected by SNI, HTTPS redirect.
- Reverse proxy to multiple upstreams with failover.
- Anti-bot challenge (JS proof-of-work) and auth challenge (password, brute
  force protection).
- Dynamic HTML/JS protection: content is encoded differently on every load,
  against data harvesting (scraping).
- Automatic HTTPS with Let's Encrypt, HTTP/2, HSTS; custom SecLang rules;
  Prometheus metrics.
- White-label block page with an Event ID.
- White-label web admin console: dashboard, applications, events (block an IP
  or report a false positive with one click), certificates; multiple accounts
  with admin/viewer roles and two-factor authentication (TOTP).
- Attack event log and management API
  ([OpenAPI spec](docs/api/README.md)).

![Console](docs/images/console-dashboard.png)

**Cluster & DNS** (`cluster/`, written from scratch):

- One control plane manages many WAF nodes in many regions.
- Per-node health checks from heartbeats, engine health and HTTP probes.
- Drain a node for maintenance; adjust the weight of each node.
- Configuration replication (sites, certificates…) from the primary node to
  the whole cluster, translating cross-reference IDs automatically.
- Authoritative DNS: answers only with healthy node IPs, weighted, prefers
  the client's region via EDNS Client Subnet, automatic failover.
- White-label dashboard (name, colour, logo), with statistics and attack
  events collected centrally from every node.

**Integrations:**

- MCP server for AI (`mcp_server/`).
- Plugins for Ingress-NGINX, Kong and lua-resty-t1k (`sdk/`).

## Repository layout

| Directory | Contents |
|---|---|
| `waf/` | **HiTechCloud WAF Engine** (Go, Coraza + CRS) — see [docs/en/engine.md](docs/en/engine.md) |
| `compose.yaml`, `scripts/manage.py` | Upstream engine stack (third-party images, OEM agreement required, see [docs/LICENSING.vi.md](docs/LICENSING.vi.md)) |
| `cluster/` | Controller, agent and DNS for the cluster (Go) — see [docs/en/cluster.md](docs/en/cluster.md) |
| `branding/console/` | White-label overlay for the console image |
| `mcp_server/` | HiTechCloud WAF MCP Server |
| `management/` | management/tcontrollerd source (legacy) |
| `sdk/` | Gateway integration plugins |
| `docs/api/` | OpenAPI 3.1 specs of the engine and controller APIs — see [docs/api/README.md](docs/api/README.md) |
| `docs/en/` | English documentation (the Vietnamese originals are in `docs/*.vi.md`) |

## Getting started

```bash
curl -fsSLO https://github.com/hitechcloud-vietnam/HiTechCloudWAF/releases/latest/download/install.sh
sudo bash install.sh node            # one WAF node + console
```

Multi-node cluster, DNS and Docker: [docs/en/install.md](docs/en/install.md);
architecture in [docs/en/cluster.md](docs/en/cluster.md).

## License

GPL-3.0, see [LICENSE.md](LICENSE.md). This is a modified version of the
SafeLine project (Chaitin Tech), see [NOTICE.md](NOTICE.md). The engine
Docker images have their own terms, see
[docs/LICENSING.vi.md](docs/LICENSING.vi.md).
