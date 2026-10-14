Tiếng Việt: [cluster.vi.md](../cluster.vi.md)

# HiTechCloud WAF Cluster — multiple nodes + DNS

```
                    ┌──────────────── Control plane ────────────────┐
  Admin ──────────► │ hcw controller :7443  (dashboard + API)        │
                    │   │  reads configuration                       │
                    │   ▼                                            │
                    │ WAF engine "primary" (console :9443)           │
                    └───────────▲───────────────────▲────────────────┘
                     heartbeat  │  config snapshot  │ endpoints (pool)
             ┌──────────────────┼──────────┐        │
             │                  │          │   ┌────┴─────────┐   ┌──────────────┐
     ┌───────┴──────┐   ┌───────┴──────┐   │   │ hcw dns #1   │   │ hcw dns #2   │
     │ Node HN-01   │   │ Node HCM-01  │ … │   │ (NS1)        │   │ (NS2)        │
     │ hcw agent    │   │ hcw agent    │   │   └──────▲───────┘   └──────▲───────┘
     │ WAF engine   │   │ WAF engine   │   │          │ DNS queries      │
     └──────▲───────┘   └──────▲───────┘   │          └────── Users ─────┘
            └──── HTTP/S traffic ─────────────────────────────┘
```

## Components (`cluster/`, binary `hcw`)

| Command | Runs on | Purpose |
|---|---|---|
| `hcw controller` | Admin machine | Node registry, health checks (heartbeat + HTTP probe), drain/weight, configuration snapshot from the primary engine, white-label dashboard |
| `hcw agent` | Every WAF node | Sends heartbeats (CPU, RAM, disk, engine health), applies the configuration (sites, certs…) to the local engine through its API |
| `hcw dns` | ≥ 2 machines (NS1/NS2) | Authoritative DNS: answers only with the IPs of healthy nodes in the pool; weighted, prefers a region by EDNS Client Subnet or by country (GeoDNS), optional fail-open; static records (A, AAAA, CNAME, TXT, MX, NS, SRV, CAA), wildcards, subdomain delegation |
| `hcw token` | – | Generates a random token |

### Node health

A node is considered healthy when all 3 conditions hold:

1. Its latest heartbeat is no older than `heartbeat_timeout`.
2. Its local engine answers the health API.
3. Its `probe_url` (if any) returns a status < 500. The controller calls the
   probe itself, and the URL must point at the node's own IP to prevent SSRF.

A node being **drained** is removed from DNS but stays in the cluster (used
during maintenance).

### Configuration replication

The controller reads the resources declared in
`controller.primary.resources` from the primary engine and builds a snapshot
with a `revision`. When an agent sees a new revision, it matches objects by
`key_fields`:

- creates missing objects and updates objects that differ;
- deletes extra objects if `prune: true`;
- translates cross-reference IDs between nodes automatically (for example
  `site.cert_id` → `cert`).

Each engine's API token stays on that node and never passes through the
controller.

> The default API paths and field names in `examples/controller.yaml` must be
> checked against the API documentation of the engine version you run. Enable
> `prune` only after checking.

### Central statistics and events

With the HiTechCloud engine, every agent heartbeat also carries:

- the node's request/block counters;
- the new attack events since the previous heartbeat (at most 100 each time).

The controller sums these into cluster-wide figures and keeps the latest 5000
events in memory. View them on the dashboard or with
`GET /v1/events?limit=&node=` (admin).

### Node enrollment and per-node secrets

Every node authenticates with its **own secret**, bound to its node ID,
instead of a token shared by all nodes:

1. An admin creates a one-time **enrollment token** on the dashboard
   (*Đăng ký node* – node enrollment section) or with
   `POST /v1/enroll-tokens`, optionally bound in advance to a `node_id`,
   `pools`, `region`, with an expiry (`expires_in`, default 24 hours, at most
   30 days). The token (`hcwe_...`) is shown **only once**.
2. On the node, write the token to a file and install the agent:
   `install.sh agent --controller https://ctl:7443 --enroll-token-file enroll.token --ca ca.crt`
   (agent.yaml: `enroll_token_file: /etc/hcw/secrets/enroll.token`).
3. On first start the agent calls `POST /v1/enroll` once, receives a **node
   secret** (`hcwn_...`, 256 random bits) and stores it in
   `<data_dir>/node-credential.json` (mode 0600). From then on it uses that
   secret for heartbeats and snapshots; after a restart it reuses the stored
   secret instead of enrolling again. A used token cannot be used again.

The controller stores only **SHA-256 hashes** of tokens and secrets, in
`credentials_file` (default `node-credentials.json` next to `state_file`, mode
0600), and compares them in constant time. Rules:

- Node A's secret can only report for node A: a heartbeat with another `id`
  is refused with **403**; attack events are always attributed to the
  secret's node.
- When the token sets `pools` / `region`, the controller enforces them and
  ignores what the agent declares itself.
- Token not bound to a `node_id`: the node ID is the `id` in agent.yaml, or
  else the hostname (lower-cased); it cannot take the ID of a node holding an
  active secret (409). A token bound to a `node_id` other than the agent's
  `id` → 403.
- Once a node ID has enrolled, the shared token is **never** accepted for that
  node again (even after revocation) — it can only enroll again with a new
  token.

**Revocation**: deleting a node (dashboard, or `DELETE /v1/nodes/{id}`) also
revokes its secret; the agent gets 401 and logs that it needs a new token.
Unused enrollment tokens are revoked with `DELETE /v1/enroll-tokens/{id}`.

**Rotation**: the *Đổi secret* (rotate secret) button on the dashboard or
`POST /v1/nodes/{id}/rotate` creates a new token bound to the node (keeping
its pools/region). Overwrite `enroll_token_file` on the node with the new
token: the agent re-reads the file every interval, notices the different
token and enrolls again; the old secret stops working as soon as enrollment
completes (no restart needed). Pass `{"revoke_current": true}` to invalidate
the old secret immediately.

#### Migrating from the shared token (`node_token`)

`node_token` keeps working (backward compatible) but is **deprecated**: the
controller logs a warning at start-up and once an hour for each node still
using it. The dashboard's *Xác thực* (authentication) column (`auth` in
`GET /v1/nodes`) shows whether a node uses `node_secret` or `shared_token`.
Steps:

1. Upgrade the controller and the agents (no configuration change needed; the
   cluster runs as before).
2. For each node: create an enrollment token bound to the node's `node_id`,
   write it to `/etc/hcw/secrets/enroll.token`, add `enroll_token_file:` to
   agent.yaml (`node_token_file` may stay — the agent only falls back to the
   shared token while it is not enrolled) and restart the agent. Or re-run
   `install.sh agent ... --enroll-token-file enroll.token`.
3. Once every node shows a per-node secret, set `require_enrollment: true` in
   controller.yaml and restart the controller: the shared token is refused
   (401), and `node_token_file` can be removed from the controller and the
   nodes.

![Cluster dashboard](../images/cluster-dashboard.png)

## DNS

### Choosing nodes by region

For a pool record (`pool: web`), DNS answers only with the healthy nodes of
the pool, picked at random by weight (`weight`), at most `max_answers`
addresses. The client address is the **EDNS Client Subnet** (ECS) when the
resolver sends one, otherwise the resolver's own address. The region is
determined in this order:

1. the record's `prefer_region`: the first CIDR containing the client
   address;
2. `prefer_country`: the client's country (GeoIP lookup) is in `countries`;
3. `prefer_country`: the client's continent is in `continents`.

The first step that yields a region with healthy nodes returns only that
region's nodes; a region without healthy nodes moves on to the next step; if
nothing matches (or there is no GeoIP database), every healthy node is
returned as before. When the answer depends on the client address, DNS
returns ECS with a scope equal to the subnet length; for answers that do not
depend on the client (static records), the scope is 0 so resolvers can share
their cache.

### GeoDNS by country

Needs a country database in `.mmdb` format (MaxMind GeoLite2-Country or DB-IP
Country Lite, both free):

```yaml
dns:
  geoip_db: /etc/hcw/geoip/country.mmdb   # replacing the file reloads it (on refresh)
  pools:                                   # defaults for every record of the pool
    web:
      prefer_country:
        - {countries: [VN], region: hn}
        - {countries: [TH, LA, KH, MY, SG], region: hcm}
        - {continents: [AS, OC], region: hcm}   # AF AN AS EU NA OC SA
  zones:
    - name: waf.hitechcloud.vn
      records:
        - {name: edge, pool: web}
        - name: vip
          pool: web
          prefer_country:                  # replaces the pool's rules
            - {countries: [VN, TH], region: asia}
```

- Country codes are ISO 3166-1 alpha-2; a country match wins over a continent
  match, and among rules of the same kind the first one wins.
- `prefer_region` (CIDR) is always tried before `prefer_country`.
- The database is loaded into RAM; when the file changes (mtime/size), DNS
  reloads it on the next `refresh` cycle and keeps the old database on error.
  Update it periodically with cron (for example monthly): write to a temporary
  file, then `mv` it over the old one.
- Without `geoip_db`, `prefer_country` rules are ignored (with a warning at
  start-up); a `geoip_db` that is declared but cannot be opened stops DNS from
  starting.

### Static records

Besides pool records, a zone holds static `A`, `AAAA`, `CNAME`, `TXT`, `MX`,
`NS`, `SRV` and `CAA` records from two sources:

1. **Configuration file**: each DNS server's `dns.yaml` (the zone's
   `records`).
2. **Controller**: managed on the dashboard (*Bản ghi DNS tĩnh* – static DNS
   records section) or through the `/v1/dns/records` API. The controller
   stores them in `dns_records_file` (default `dns-records.json` next to
   `state_file`; written to a temporary file then renamed, like the node
   state). DNS servers download the list on the same `refresh` cycle as the
   pools (with `ETag`; when nothing changed the controller returns 304); if
   the controller is unreachable, DNS keeps the previous list. Each DNS server
   only serves records whose `zone` matches the name of a zone in its own
   `dns.yaml`.

The `value` syntax is the zone file syntax; a name without a trailing dot is
taken as inside the zone (`mail` → `mail.<zone>.`):

| Type | Example `value` |
|---|---|
| A / AAAA | `203.0.113.10` / `2001:db8::10` |
| CNAME | `edge.waf.hitechcloud.vn.` |
| TXT | `v=spf1 include:_spf.example.vn -all` (without double quotes the text is kept verbatim and split into 255-byte chunks automatically; with double quotes the zone file syntax applies) |
| MX | `10 mail.example.vn.` |
| NS | `ns1.example.net.` |
| SRV | `10 60 5060 sip.example.vn.` |
| CAA | `0 issue "letsencrypt.org"` |

Answer rules:

- **Apex**: SOA and NS are built from the zone's `ns`, `hostmaster` and
  `ttl`; static NS records at `@` are added to the NS list. The SOA serial is
  the larger of the zone's `serial` and the controller's serial (which
  increases after every change).
- **NXDOMAIN / NODATA**: a name that does not exist → NXDOMAIN; a name that
  exists (including intermediate names such as `deep` when `a.b.deep` exists)
  but has no record of the requested type → empty NOERROR. Both carry the SOA
  in the authority section.
- **CNAME**: not allowed at `@` and not alongside other data on the same name.
  A target inside a zone served by this DNS server is included in the answer
  (at most 8 hops, loop-safe); targets outside are left to the resolver.
- **Wildcard** `*.app`: answers for every name under `app` that does not
  exist (RFC 4592); the name in the answer is the name that was asked. Pool
  records can use wildcards too (`{name: "*.cdn", pool: web}`).
- **NS below the apex** (for example `lab`): subdomain delegation — returns a
  referral (not authoritative) with A/AAAA glue when the name server is inside
  the zone.
- Name clashes between the configuration file and the controller (CNAME
  clashing with other data, duplicate records): **the configuration file
  wins**, the controller's record is ignored and logged.

API example:

```bash
API=https://controller.example.vn:7443/v1/dns/records
curl -H "Authorization: Bearer $ADMIN" "$API?zone=waf.hitechcloud.vn"
curl -H "Authorization: Bearer $ADMIN" -d '{"zone":"waf.hitechcloud.vn","name":"@","type":"MX","value":"10 mail.hitechcloud.vn.","ttl":300}' "$API"
curl -X PUT -H "Authorization: Bearer $ADMIN" -d '{"zone":"waf.hitechcloud.vn","name":"www","type":"A","value":"203.0.113.11"}' "$API/<id>"
curl -X DELETE -H "Authorization: Bearer $ADMIN" "$API/<id>"
```

Record fields: `zone`, `name` (`@`, `www`, `*.app`), `type`, `value`, `ttl`
(0 = the zone's TTL, at most 604800), `comment`. The controller checks the
syntax and conflicts before saving (syntax error → 400, conflict/duplicate →
409).

## Quick deployment

```bash
# 1) Control plane
sudo cluster/deploy/bootstrap-controller.sh controller.example.vn 203.0.113.5
sudo cp cluster/examples/controller-hcw-engine.yaml /etc/hcw/controller.yaml   # adapt it
# Create an API token on the primary console → /etc/hcw/secrets/primary-engine.token
docker compose -f cluster/deploy/compose.controller.yaml up -d --build

# 2) Each WAF node (already running the hcw-waf engine, e.g. `docker compose up -d hcw-waf`
#    in waf/deploy/)
#    copy ca.crt from the controller to /etc/hcw/tls/, create an enrollment
#    token on the dashboard and write it to /etc/hcw/secrets/enroll.token
sudo cp cluster/examples/agent.yaml /etc/hcw/agent.yaml             # edit id/ip/region/pools
docker compose -f cluster/deploy/compose.node.yaml up -d --build

# 3) DNS (≥ 2 machines) – copy ca.crt + dns.token
sudo cp cluster/examples/dns.yaml /etc/hcw/dns.yaml
docker compose -f cluster/deploy/compose.dns.yaml up -d --build
```

`controller-hcw-engine.yaml` is the template for the `hcw-waf` engine;
`controller.yaml` is a generic template with every option commented. On a
node, both the engine and the agent can be run with `waf/deploy/compose.yaml`
instead of `compose.node.yaml` (agent only).

At the domain registrar, declare `ns1`/`ns2` (glue records) for the zone,
for example `waf.hitechcloud.vn`. Customers point a CNAME of their domain to
`edge.waf.hitechcloud.vn` (or to a dedicated record per customer).

Dashboard: `https://controller.example.vn:7443/`, log in with `admin.token`.

## Controller API

Full specification: [`docs/api/cluster.openapi.yaml`](../api/cluster.openapi.yaml)
(see [docs/api/README.md](../api/README.md)).

| Method & path | Token | Description |
|---|---|---|
| `GET /healthz` | – | liveness |
| `POST /v1/heartbeat` | node secret (or the deprecated shared node token) | agent report |
| `GET /v1/config/snapshot` | node secret (or the deprecated shared node token) | configuration snapshot |
| `POST /v1/enroll` | enrollment token | agent exchanges a one-time token for its node secret |
| `GET/POST /v1/enroll-tokens`, `DELETE /v1/enroll-tokens/{id}` | admin | create / list / revoke enrollment tokens |
| `GET /v1/nodes`, `GET/PATCH/DELETE /v1/nodes/{id}` | admin | node management (`{"drain":true}`, `{"weight_override":50}`); `DELETE` also revokes the node secret |
| `POST /v1/nodes/{id}/rotate` | admin | new token to replace the node's secret (`{"revoke_current":true}` revokes at once) |
| `GET /v1/pools` | admin | pools + endpoints |
| `GET /v1/events` | admin | cluster-wide attack events |
| `GET /v1/pools/{pool}/endpoints` | dns/admin | used by DNS |
| `GET /v1/dns/records?zone=` | dns/admin | static DNS records + `serial` (supports `If-None-Match`) |
| `POST /v1/dns/records`, `GET/PUT/DELETE /v1/dns/records/{id}` | admin | static DNS record management |
| `GET/POST /v1/sync` | admin | status / sync now |

## Testing

```bash
cd cluster && go vet ./... && go test -race ./...
```

Manual DNS check on a high port (no root needed), with `listen: ":5353"`:

```bash
dig @127.0.0.1 -p 5353 waf.hitechcloud.vn SOA
dig @127.0.0.1 -p 5353 edge.waf.hitechcloud.vn A +subnet=14.160.1.0/24
dig @127.0.0.1 -p 5353 x.cdn.waf.hitechcloud.vn A
```

## Security notes

- Nodes may not declare loopback, link-local or multicast addresses; the
  controller's probes also refuse to connect to those ranges (set
  `allow_loopback_nodes: true` only for lab tests).
- Enrollment tokens and node secrets are only stored as hashes; tokens are
  sent to the controller over TLS (the agent requires `https://` except on
  loopback), so always pin the CA (`controller_ca`).
- Every node has its own secret (see *Node enrollment*): a compromised node
  cannot send heartbeats/events on behalf of another node (403). Set
  `require_enrollment: true` once migration is complete to get rid of the
  shared token entirely.
- A registered node cannot change its IPv4/IPv6 through a heartbeat (prevents
  taking over a node with the shared token). When a node really changes IP,
  delete it on the dashboard or with `DELETE /v1/nodes/{id}` and let the agent
  register again (a node with its own secret needs a new enrollment token);
  or set `allow_address_change: true`.
- The agent only replicates configuration collections under `/api/open/`
  (never users, backup/restore, audit, alerts or `me/`).
- DNS servers require `https://` to the controller (except on loopback).
- `install.sh` checks the binary's SHA256 against the release `SHA256SUMS`;
  use `--enroll-token-file` / `--node-token-file` / `--dns-token-file` so
  tokens do not appear on the command line.
