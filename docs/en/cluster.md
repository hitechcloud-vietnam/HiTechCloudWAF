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

![Cluster dashboard](../images/cluster-dashboard.png)

## Quick deployment

```bash
# 1) Control plane
sudo cluster/deploy/bootstrap-controller.sh controller.example.vn 203.0.113.5
sudo cp cluster/examples/controller.yaml /etc/hcw/controller.yaml   # adapt it
# Create an API token on the primary console → /etc/hcw/secrets/primary-engine.token
docker compose -f cluster/deploy/compose.controller.yaml up -d --build

# 2) Each WAF node (already running the engine stack with compose.yaml at the repo root)
#    copy ca.crt + node.token from the controller to /etc/hcw/...
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
| `POST /v1/heartbeat` | node | agent report |
| `GET /v1/config/snapshot` | node | configuration snapshot |
| `GET /v1/nodes`, `GET/PATCH/DELETE /v1/nodes/{id}` | admin | node management (`{"drain":true}`, `{"weight_override":50}`) |
| `GET /v1/pools` | admin | pools + endpoints |
| `GET /v1/events` | admin | cluster-wide attack events |
| `GET /v1/pools/{pool}/endpoints` | dns/admin | used by DNS |
| `GET/POST /v1/sync` | admin | status / sync now |

## Testing

```bash
cd cluster && go vet ./... && go test -race ./...
```
