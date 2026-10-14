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
| `hcw dns` | ≥ 2 machines (NS1/NS2) | Authoritative DNS: answers only with the IPs of healthy nodes in the pool; weighted, prefers the client's region via EDNS Client Subnet, optional fail-open |
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
   (*Đăng ký node* section) or with `POST /v1/enroll-tokens`, optionally bound
   to a `node_id`, `pools`, `region`, with an expiry (`expires_in`, default 24
   hours, at most 30 days). The token (`hcwe_...`) is shown **once**.
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
  ignores what the agent reports.
- Unbound token: the node ID is the agent's configured `id`, else its
  lower-cased hostname; it cannot take the ID of a node holding an active
  secret (409). A token bound to a `node_id` other than the agent's `id` → 403.
- Once a node ID has enrolled, the shared token is **never** accepted for it
  again (even after revocation); it can only enroll again with a new token.

**Revocation**: deleting a node (dashboard, or `DELETE /v1/nodes/{id}`) also
revokes its secret; the agent gets 401 and logs that it needs a new token.
Unused enrollment tokens are revoked with `DELETE /v1/enroll-tokens/{id}`.

**Rotation**: the *Đổi secret* button or `POST /v1/nodes/{id}/rotate` creates a
new token bound to the node (keeping its pools/region). Overwrite the node's
`enroll_token_file` with it: the agent re-reads the file every interval,
notices the new token and enrolls again; the old secret stops working as soon
as it has (no restart needed). Pass `{"revoke_current": true}` to invalidate
the old secret immediately.

#### Migrating from the shared `node_token`

`node_token` keeps working (backward compatible) but is **deprecated**: the
controller logs a warning at start-up and once an hour for each node still
using it. The dashboard's *Xác thực* column (`auth` in `GET /v1/nodes`) shows
whether a node uses `node_secret` or `shared_token`. Steps:

1. Upgrade the controller and the agents (no configuration change needed; the
   cluster runs as before).
2. For each node: create an enrollment token bound to the node's `node_id`,
   write it to `/etc/hcw/secrets/enroll.token`, add `enroll_token_file:` to
   agent.yaml (`node_token_file` may stay: the agent only falls back to the
   shared token while it is not enrolled) and restart the agent. Or re-run
   `install.sh agent ... --enroll-token-file enroll.token`.
3. Once every node shows a per-node secret, set `require_enrollment: true` in
   controller.yaml and restart the controller: the shared token is refused
   (401) and `node_token_file` can be removed from the controller and nodes.

![Cluster dashboard](../images/cluster-dashboard.png)

## Quick deployment

```bash
# 1) Control plane
sudo cluster/deploy/bootstrap-controller.sh controller.example.vn 203.0.113.5
sudo cp cluster/examples/controller.yaml /etc/hcw/controller.yaml   # adapt it
# Create an API token on the primary console → /etc/hcw/secrets/primary-engine.token
docker compose -f cluster/deploy/compose.controller.yaml up -d --build

# 2) Each WAF node (already running the engine stack with compose.yaml at the repo root)
#    copy ca.crt from the controller to /etc/hcw/tls/, create an enrollment
#    token on the dashboard and write it to /etc/hcw/secrets/enroll.token
sudo cp cluster/examples/agent.yaml /etc/hcw/agent.yaml             # edit id/ip/region/pools
docker compose -f cluster/deploy/compose.node.yaml up -d --build

# 3) DNS (≥ 2 machines) – copy ca.crt + dns.token
sudo cp cluster/examples/dns.yaml /etc/hcw/dns.yaml
docker compose -f cluster/deploy/compose.dns.yaml up -d --build
```

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
| `GET/POST /v1/sync` | admin | status / sync now |

## Testing

```bash
cd cluster && go vet ./... && go test -race ./...
```
