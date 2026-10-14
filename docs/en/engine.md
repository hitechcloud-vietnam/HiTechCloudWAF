Tiếng Việt: [engine.vi.md](../engine.vi.md)

# HiTechCloud WAF Engine (`waf/`)

HiTechCloud's own WAF engine, fully open source and **independent of any
third-party engine image**. Binary: `hcw-waf`.

## How a request is processed

```
Client ─► listener (HTTP / HTTPS by SNI)
          │
          ├─ pick the site by Host (exact name, wildcard *.domain, or "_")
          ├─ HTTPS redirect (optional)
          ├─ IP ACL: ip_deny → 403, ip_allow (if set) → 403
          ├─ Path rules (allow / deny / skip_waf / rate_limit)
          ├─ Rate limit per IP/site → 429 + block duration
          ├─ Auth challenge (password) → login page
          ├─ Anti-bot challenge (JS proof-of-work) → browser check page
          ├─ OWASP Coraza + Core Rule Set v4 (SQLi, XSS, RCE, LFI/RFI,
          │   path traversal, scanners, protocol attacks…) → 403
          ├─ Reverse proxy → upstream (round-robin; a failing upstream is skipped for 10s)
          └─ Dynamic protection: encode HTML/JS in the response (optional)
```

The block page carries the HiTechCloud brand and shows an **Event ID** for
lookups. Every block produces an event, kept in memory and written to a JSONL
file.

## Protection settings of each site

| Field | Meaning |
|---|---|
| `mode` | `block`, `monitor` (log only), `off` (plain proxy) |
| `paranoia` | 1–4. Default 1, few false positives. PL3–4 catch more but need tuning |
| `anomaly_threshold` | CRS score threshold that blocks (default 5) |
| `disabled_rules` | CRS rule IDs disabled for the site, for false positives |
| `rate_limit` | `{requests, window_sec, block_sec}` |
| `ip_allow` / `ip_deny` | Lists of IPs or CIDRs |
| `ports` | `"80"`, `"443_ssl"` (an `_ssl` port requires `cert_id`) |
| `upstreams` | `http(s)://host:port`, several upstreams allowed |
| `upstream_host`, `upstream_insecure`, `redirect_https` | Proxy options |
| `auto_tls` | Obtain and renew Let's Encrypt certificates automatically (needs `acme.enabled`) |
| `hsts` | Add `Strict-Transport-Security` to HTTPS responses |
| `country_allow` / `country_deny` | ISO country codes, e.g. `VN`. Needs `geoip_db` on the node |
| `dynamic_protection` | Encode HTML/JS on every response, against data harvesting (see below) |
| `rules` | Path rules (see below) |
| `health_check` | `{path, interval_sec, timeout_sec, unhealthy, healthy}`: active upstream checks |
| `custom_rules` | The site's own SecLang rules (IDs 1–99999, no `Include` and no file reads) |

The complete object, with every field, default and range, is the `Site`
schema in [`docs/api/waf.openapi.yaml`](../api/waf.openapi.yaml).

### Path rules (`rules`)

```json
"rules": [
  {"path": "/login", "exact": true, "methods": ["POST"], "action": "rate_limit",
   "rate_limit": {"requests": 5, "window_sec": 60, "block_sec": 300}},
  {"path": "/webhook", "action": "allow", "ips": ["203.0.113.0/24"]},
  {"path": "/api/upload", "action": "skip_waf"},
  {"path": "/wp-admin", "action": "deny"}
]
```

| Action | Effect |
|---|---|
| `allow` | Whitelist: skip rate limits, anti-bot, password and WAF (IP/country ACLs still apply) |
| `deny` | Return 403 |
| `skip_waf` | Skip only the OWASP CRS filter |
| `rate_limit` | A separate rate limit for the path (in addition to the site-wide limit) |

- Rules are evaluated in order; `allow` and `deny` stop the evaluation of the
  following rules.
- `path` matches as a prefix, or exactly when `exact` is set.
- `methods` and `ips` are optional conditions.
- In the console, they are managed in the **Path rules** section of the
  application form.

### Anti-bot challenge (`bot_challenge`)

`{"enabled": true, "difficulty": 16, "ttl_sec": 3600, "exclude_paths": ["/api/"]}`

The browser has to solve a SHA-256 proof-of-work puzzle in JavaScript.
Measured on Chromium at difficulty 16: 140–575 ms. Once solved, the browser
receives an `hcw_bot` cookie (HttpOnly, HMAC-signed, bound to the site and
the IP; for IPv6, bound to the /64). Scripts, curl and bots without a JS
engine are stopped. A nonce is only usable for 5 minutes, on the same site,
from the same IP.

Use `exclude_paths` for APIs, webhooks and mobile apps, since these clients
cannot run JS.

### Auth challenge (`auth`)

`{"enabled": true, "password": "…", "ttl_sec": 28800, "exclude_paths": []}`

- The password is hashed with bcrypt as soon as it is saved; the API only
  returns `password_hash`.
- Changing the password invalidates every existing login session.
- 10 failures within 10 minutes lock the client out for 15 minutes.
- Log out: `/.hcw/logout`.

The `/.hcw/` path is reserved by the engine on every site.

**Cluster:** set the same `challenge_secret_file` on all nodes. When DNS moves
a visitor to another node, the visitor does not have to solve the challenge
again.

Binary bodies (octet-stream, images, video, zip, pdf, gRPC) only have their
headers inspected; their content is not scanned. For JSON/form bodies, the
engine inspects the first `body_limit_kb`; the rest is still passed in full to
the upstream.

Tip: run in `monitor` for a few days to review the log, add `disabled_rules`
for rules that cause false positives, then switch to `block`.

### Dynamic HTML/JS protection (`dynamic_protection`)

`{"html": true, "js": true, "paths": ["/san-pham/"]}`

**HTML:** every returned page is replaced by a small loader page containing
the original content encoded with a random key unique to that response.
Variable names change every time as well. The browser decodes it and rebuilds
the whole document, including `<head>`, CSS, external scripts and inline
scripts. Data harvesting tools (curl, Scrapy, BeautifulSoup…) only get a
meaningless blob that differs on every reload.

**JavaScript:** JS files are wrapped and encoded. When run, the original code
is injected into a new `<script>` tag, so it behaves exactly as before: global
variables, top-level `let`/`const`/`class` and `"use strict"` are all kept.

**Not applied (response left unchanged)** for:

- responses with their own CSP (the CSP would block the loader page);
- ES modules (`import`/`export`);
- a charset other than UTF-8, brotli compression, bodies larger than 4 MB;
- requests other than GET, or a status other than 200.

Gzip content from the upstream is decompressed automatically. Encoded
responses carry `Cache-Control: no-store` and the `X-HCW-Protected` header.

**Notes:**

- This is **obfuscation**, not secure encryption: the key ships with the
  page. The goal is to raise the cost of data harvesting and code analysis.
- Search engines that run JS (Googlebot) can still read the content, but you
  should limit protection with `paths` to the areas that need it (prices,
  proprietary content) so SEO is not affected.
- Tested on real Chromium: titles, CSS, external/inline scripts and
  Vietnamese text all render correctly, with no console errors.

### Automatic HTTPS (Let's Encrypt)

Enable `acme.enabled` in `waf.yaml`, then enable `auto_tls` on sites with a
`443_ssl` port. The engine:

- obtains certificates through HTTP-01 (port 80) or TLS-ALPN-01 (port 443),
  stores them in `data_dir/acme` and renews them automatically;
- only requests certificates for the domains of sites with `auto_tls`
  enabled, so an attacker cannot make the node request certificates for other
  domains.

For clusters, Let's Encrypt limits the number of duplicate certificates per
week. From about 5 nodes upwards, use uploaded certificates (`cert_id`) so
they are replicated to every node.

HTTPS also supports HTTP/2.

### Country blocking (GeoIP)

Set `geoip_db` in `waf.yaml` to an MMDB file. You can use:

- **DB-IP Country Lite**: free, CC BY 4.0 license, attribution to db-ip.com
  required. Quick install with `install.sh node --geoip`.
- **MaxMind GeoLite2-Country**: needs a MaxMind account.

Update the database monthly, then `systemctl kill -s HUP hcw-waf` to reload it
without a restart.

How each case is handled:

| Case | Result |
|---|---|
| IP in a country listed in `country_deny` | 403 |
| `country_allow` set and the IP is not in the list | 403 |
| `country_allow` set and the country cannot be determined | 403 |
| Only `country_deny` set and the country cannot be determined (internal IP, missing DB) | Allowed |

Every attack event records the country code.

### Alerts (Telegram, webhook)

Declared in `waf.yaml` (see `waf/examples/waf.yaml`). How it works:

- Events are grouped by (site, kind). The first event is reported within
  about 10 seconds; after that, at most one summary message is sent every
  `interval` (default 5 minutes), with the number of events, the top IPs and
  a sample request.
- `kinds` selects what to report: `waf`, `geo`, `ip_deny`, `ip_allow`,
  `rate_limit`, `bot`, `auth`. By default only `waf` is reported.
- **Telegram:** create a bot with @BotFather, add it to a group, fill in
  `chat_id`.
- **Webhook:** receives JSON (`node`, `site`, `kind`, `count`, `top_ips`,
  `sample`). The `X-HCW-Signature: sha256=<HMAC-SHA256(secret, body)>` header
  lets you verify that the message comes from the WAF.
- Test the configuration: the **Send test alert** button in the console, or
  `POST /api/open/alerts/test`.

### Upstream health checks

`"health_check": {"path": "/healthz", "interval_sec": 10, "timeout_sec": 3, "unhealthy": 3, "healthy": 2}`

- The engine requests `path` on each upstream periodically, sending the
  site's Host.
- An upstream that fails `unhealthy` times in a row (connection error or
  status ≥ 400) is taken out of the load-balancing rotation. Once it succeeds
  `healthy` times in a row, it is put back.
- The state is kept across configuration reloads.
- If every upstream is failing, the engine still tries one upstream instead of
  failing every request.
- See the state in the console's application list (green/red dot) or through
  `GET /api/open/upstreams`.
- WebSocket and other upgraded protocols (Upgrade) pass through the WAF
  normally.

### Access log

```yaml
access_log:
  file: /var/lib/hcw-waf/access.log
  max_size_mb: 100   # rotates to access.log.1 … .N
  max_files: 5
```

Each request writes one JSON line with the fields `time`, `site_id`, `host`,
`client_ip`, `country`, `method`, `uri`, `proto`, `tls`, `status`, `bytes`,
`duration_ms`, `user_agent`, `referer`, `action` and `event_id` (when
blocked). `action` takes one of: `proxied`, `blocked`, `challenged`,
`redirected`, `error`, `acme`.

The log is written asynchronously so it does not slow traffic down; if the
disk cannot keep up, lines are dropped rather than slowing requests. The JSON
format can be read directly by Filebeat/Vector/Loki.

### Monitoring (Prometheus)

`GET /api/open/metrics`, authenticated with a Bearer token. Metrics include
`hcw_requests_total`, `hcw_blocked_total`, `hcw_rate_limited_total`,
`hcw_acl_blocked_total`, `hcw_bot_failed_total`, `hcw_monitored_total` (per
site), plus `hcw_sites` and `hcw_uptime_seconds`.

```yaml
scrape_configs:
  - job_name: hcw-waf
    scheme: https
    tls_config: {insecure_skip_verify: true}
    authorization: {credentials_file: /etc/prometheus/hcw.token}
    metrics_path: /api/open/metrics
    static_configs: [{targets: ["10.0.0.11:9443", "10.0.0.12:9443"]}]
```

## Web admin console

The console is built into `hcw-waf` and served on the same address as the
API (`https://127.0.0.1:9443/`). There are two ways to log in:

- **User accounts** (recommended). The first time, log in with the API token
  and go to the **Users** page to create an administrator account. There are
  two roles: `admin` (full access) and `viewer` (read only; the server refuses
  every modifying action and the interface hides the corresponding buttons).
- **API token**: admin rights, intended for automation and the cluster agent.

**Account security:**

- Passwords are ≥ 10 characters, stored as bcrypt.
- Login sessions expire after 12 hours. Changing a user's password or role,
  or deleting the account, ends that user's open sessions.
- 10 failures within 15 minutes temporarily lock the IP address.
- **Two-factor authentication (TOTP):** go to **Account**, scan the QR code
  with Google/Microsoft Authenticator or Authy, then enter a code to confirm.
  From then on every login needs an extra 6-digit code; each code can only be
  used once.
- Lost phone: another admin clicks **Reset 2FA** for that user.
- Accounts are stored in `data_dir/users.json`. The last admin cannot be
  deleted or demoted.

![Enabling 2FA](../images/console-2fa.png)

**System page** (admins only):

- **Backup:** download every application and certificate (with private keys)
  as one JSON file.
- **Restore:** replace the whole configuration with a backup file. Every site
  and certificate in the file is validated first; a single invalid item
  rejects the whole file and the running configuration is kept. API:
  `GET /api/open/backup`, `POST /api/open/restore`.
- **Audit log:** every change through the API/console and every login
  (successful or failed) is recorded: who, from which IP, what action, with
  what result, along with the request body. Passwords, keys, tokens and 2FA
  codes are masked as `***`. Stored in `data_dir/audit.log`; API
  `GET /api/open/audit`.

Features:

- **Overview:** requests and blocks in the last 60 minutes, a per-minute
  chart, recent attack types, statistics per application.
- **Applications:** add, edit, delete; configure CRS mode, rate limit, ACL,
  anti-bot, password, HTTPS and proxy options.
- **Attack events:** filter by application, see the matched rules in detail.
  **Block IP** (adds the IP to the denylist) and **Report false positive**
  (disables the matched rules for that site) buttons.
- **Certificates:** upload PEM certificates; warns when they are about to
  expire.

Name, colour and logo follow the `brand` section of the configuration
(white label). The console uses a strict CSP, has no inline scripts, and
inserts all data through `textContent` to prevent XSS.

By default the console only listens on `127.0.0.1`. For remote access, either
use an SSH tunnel, or set `api.listen: 0.0.0.0:9443` together with
`api.allow` to restrict which IPs may connect.

![Overview](../images/console-dashboard.png)
![Events](../images/console-events.png)
![Applications](../images/console-site.png)

## Management API

Full specification: [`docs/api/waf.openapi.yaml`](../api/waf.openapi.yaml)
(see [docs/api/README.md](../api/README.md) for usage and examples).

Default address `https://127.0.0.1:9443`. Send the token in the
`X-HCW-API-TOKEN` header or as `Authorization: Bearer`. Every response has the
form `{"data": …, "err": null, "msg": ""}`.

| Method | Path | Body |
|---|---|---|
| GET | `/api/open/health` | – (no token needed) |
| GET / POST / PUT | `/api/open/site` | Site object (PUT must include `id`) |
| DELETE | `/api/open/site` | `{"ids":[1,2]}` |
| GET / POST / PUT / DELETE | `/api/open/cert` | `{"crt": PEM, "key": PEM}` |
| GET | `/api/open/events?limit=100&site_id=1` | – |
| GET | `/api/open/stats` | – |
| GET | `/api/open/timeseries` | – (last 60 minutes) |
| GET | `/api/open/info` | – (version, number of sites) |
| GET | `/api/open/brand` | – (no token needed) |
| POST | `/api/auth/login` | `{"username","password","otp"}` → `token` (send it in the `X-HCW-Session` header) |
| POST | `/api/auth/logout` | – |
| GET | `/api/open/me` | – |
| POST | `/api/open/me/password`, `/me/totp/setup`, `/me/totp/enable`, `/me/totp/disable` | – |
| GET / POST / PUT / DELETE | `/api/open/users` | user management (admin) |
| POST | `/api/open/alerts/test` | – |

Example:

```bash
TOKEN=$(cat /etc/hcw-waf/api.token)
curl -k -H "X-HCW-API-TOKEN: $TOKEN" -X POST https://127.0.0.1:9443/api/open/site -d '{
  "server_names": ["shop.example.vn"],
  "ports": ["80"],
  "upstreams": ["http://10.0.0.10:8080"],
  "rate_limit": {"requests": 300, "window_sec": 60, "block_sec": 300}
}'
```

## Running a cluster

Use `cluster/examples/controller-hcw-engine.yaml` for the controller. On each
node run `waf/deploy/compose.yaml` (engine + agent). Configuration created on
the primary node is replicated to the other nodes automatically (create,
update, delete), and DNS only answers with the IPs of healthy nodes. This
whole flow has been tested end to end with 2 real nodes.

## Tested

`go test -race ./...` covers:

- blocking SQLi, XSS, path traversal and RCE in both the query string and
  JSON/form bodies;
- legitimate requests with Vietnamese text and 3 MB uploads pass through;
- monitor mode;
- rate limits, ACLs, wildcard hosts;
- `X-Forwarded-For` is only trusted when coming through a trusted proxy;
- upstream failover;
- TLS with multiple certificates by SNI;
- API CRUD and storage.
