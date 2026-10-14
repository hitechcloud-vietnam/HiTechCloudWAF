# HiTechCloud WAF API specifications

| File | API | Served by |
|---|---|---|
| [`waf.openapi.yaml`](waf.openapi.yaml) | Engine management API (sites, certificates, events, stats, metrics, users/2FA, audit, backup/restore, upstreams, alerts) | `hcw-waf`, default `https://127.0.0.1:9443` |
| [`cluster.openapi.yaml`](cluster.openapi.yaml) | Cluster controller API (heartbeats, nodes, pools, events, sync) | `hcw controller`, default `:7443` |

Both are OpenAPI 3.1 documents written from the handlers in
`waf/internal/mgmt` and `cluster/internal/controller`. Tests in those packages
(`TestOpenAPICoversRoutes`) fail when a route is registered without being
documented, or documented without being registered, so the specs cannot drift
silently from the code.

## Viewing and validating

```bash
# Lint (any OpenAPI 3.1 validator works)
npx @redocly/cli@1.25.11 lint docs/api/waf.openapi.yaml docs/api/cluster.openapi.yaml

# Browse as HTML documentation
npx @redocly/cli@1.25.11 build-docs docs/api/waf.openapi.yaml -o waf-api.html
```

The files can also be opened in Swagger Editor or imported into Postman,
Insomnia or Bruno, and fed to OpenAPI code generators.

## Engine API

### Authentication and roles

| Header | Value | Role |
|---|---|---|
| `X-HCW-API-TOKEN` | node API token (`/etc/hcw-waf/api.token`) | `admin` |
| `Authorization: Bearer` | the same API token | `admin` |
| `X-HCW-Session` | session token from `POST /api/auth/login` | the user's role |

No token is needed for `GET /api/open/health`, `GET /api/open/brand`,
`POST /api/auth/login` and the console pages. A `viewer` may call every `GET`
route except the audit log and backup, plus logout and its own `/api/open/me/...`
routes. Each operation in the spec carries `x-required-role`
(`public`, `viewer` or `admin`).

Every JSON response is wrapped in `{"data": ..., "err": null, "msg": ""}`; on
failure `err` is a code such as `unauthorized`, `forbidden`, `invalid`,
`not_found` or `apply_failed`, and `msg` explains it. `GET /api/open/metrics`
returns the Prometheus text format instead.

The API uses a self-signed certificate unless `api.tls_cert` is set, hence
`-k` in the examples below (or pass `--cacert` with the node's certificate).

### Examples

```bash
API=https://127.0.0.1:9443
TOKEN=$(sudo cat /etc/hcw-waf/api.token)
H="X-HCW-API-TOKEN: $TOKEN"

# Liveness (no token)
curl -k $API/api/open/health

# List sites
curl -k -H "$H" $API/api/open/site

# Create a site
curl -k -H "$H" -X POST $API/api/open/site -d '{
  "server_names": ["shop.example.vn"],
  "ports": ["80"],
  "upstreams": ["http://10.0.0.10:8080"],
  "mode": "monitor",
  "rate_limit": {"requests": 300, "window_sec": 60, "block_sec": 300}
}'

# Update it (PUT replaces the whole object; take it from the list, edit, send back)
curl -k -H "$H" $API/api/open/site | jq '.data.data[] | select(.id == 1) | .mode = "block"' \
  | curl -k -H "$H" -X PUT $API/api/open/site -d @-

# Delete sites
curl -k -H "$H" -X DELETE $API/api/open/site -d '{"ids": [1]}'

# Upload a certificate
jq -n --rawfile crt fullchain.pem --rawfile key privkey.pem '{crt: $crt, key: $key}' \
  | curl -k -H "$H" -X POST $API/api/open/cert -d @-

# Latest 20 events of site 1, counters, upstream health
curl -k -H "$H" "$API/api/open/events?limit=20&site_id=1"
curl -k -H "$H" $API/api/open/stats
curl -k -H "$H" $API/api/open/upstreams

# Prometheus metrics (Bearer works too)
curl -k -H "Authorization: Bearer $TOKEN" $API/api/open/metrics

# Backup, then restore: restore takes the "data" part of the backup answer
curl -k -H "$H" $API/api/open/backup | jq .data > backup.json
curl -k -H "$H" -X POST $API/api/open/restore -d @backup.json

# Send a test alert
curl -k -H "$H" -X POST $API/api/open/alerts/test
```

With a console account instead of the API token:

```bash
SESSION=$(curl -sk -X POST $API/api/auth/login \
  -d '{"username": "alice", "password": "...", "otp": "123456"}' | jq -r .data.token)
curl -k -H "X-HCW-Session: $SESSION" $API/api/open/me
curl -k -H "X-HCW-Session: $SESSION" -X POST $API/api/auth/logout
```

A login answer of `401` with `"err": "otp_required"` means the account has
two-factor authentication: repeat the request with `otp`.

## Controller API

All protected routes take `Authorization: Bearer <token>`, with the token of
the caller's kind (see `x-required-token` in the spec):

| Token | File on the controller | Used for |
|---|---|---|
| admin | `/etc/hcw/secrets/admin.token` | dashboard, nodes, pools, events, sync |
| node | `/etc/hcw/secrets/node.token` | `POST /v1/heartbeat`, `GET /v1/config/snapshot` (agents) |
| dns | `/etc/hcw/secrets/dns.token` | `GET /v1/pools/{pool}/endpoints` (DNS servers; admin also accepted) |

Responses are plain JSON (no envelope); errors are plain-text messages.

```bash
CTL=https://ctl.waf.example.vn:7443
ADMIN=$(sudo cat /etc/hcw/secrets/admin.token)
A="Authorization: Bearer $ADMIN"

curl --cacert /etc/hcw/tls/ca.crt $CTL/healthz
curl --cacert /etc/hcw/tls/ca.crt -H "$A" $CTL/v1/nodes
curl --cacert /etc/hcw/tls/ca.crt -H "$A" $CTL/v1/pools
curl --cacert /etc/hcw/tls/ca.crt -H "$A" "$CTL/v1/events?limit=50&node=hn-01"

# Drain a node for maintenance, then put it back
curl --cacert /etc/hcw/tls/ca.crt -H "$A" -X PATCH $CTL/v1/nodes/hn-01 -d '{"drain": true}'
curl --cacert /etc/hcw/tls/ca.crt -H "$A" -X PATCH $CTL/v1/nodes/hn-01 -d '{"drain": false}'

# Replication status, and refresh the snapshot from the primary now
curl --cacert /etc/hcw/tls/ca.crt -H "$A" $CTL/v1/sync
curl --cacert /etc/hcw/tls/ca.crt -H "$A" -X POST $CTL/v1/sync
```

## Keeping the specs current

When you add or change a route:

1. Update the spec in this directory (paths, request/response schemas,
   `x-required-role` / `x-required-token`).
2. Run the tests: `cd waf && go test ./internal/mgmt/` and
   `cd cluster && go test ./internal/controller/`.
3. Lint: `npx @redocly/cli@1.25.11 lint docs/api/*.openapi.yaml`.

The route test checks paths and methods only; schemas are reviewed by hand
against the JSON tags of the Go types (`waf/internal/model`,
`waf/internal/events`, `waf/internal/users`, `cluster/internal/api`, ...).
