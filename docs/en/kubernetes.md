Tiếng Việt: [kubernetes.vi.md](../kubernetes.vi.md)

# Deploying HiTechCloud WAF on Kubernetes

There are two ways:

- **Helm chart** `deploy/helm/hitechcloud-waf/`: every option, from a single
  WAF node to a multi-pod cluster with controller, agent and DNS.
- **Plain manifests** `deploy/kubernetes/`: one WAF node, installed with
  `kubectl apply -k`, no Helm needed. The files are generated from the chart,
  so they always match it.

Images (CI pushes them to GHCR on every merge into `main`, tagged `latest` and
with the commit SHA; pin the SHA in production):

| Image | Used for |
|---|---|
| `ghcr.io/hitechcloud-vietnam/hitechcloud-waf` | the `hcw-waf` engine (proxy, WAF, console) |
| `ghcr.io/hitechcloud-vietnam/hitechcloud-waf-cluster` | `hcw controller` / `agent` / `dns` |

If the GHCR packages are private, create an image pull secret and declare it
in `imagePullSecrets`:

```bash
kubectl -n hitechcloud-waf create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io --docker-username=<user> --docker-password=<token that can read packages>
# values: imagePullSecrets: [{name: ghcr-pull}]
```

Requirements: Kubernetes ≥ 1.25, Helm 3, a default StorageClass (for the data
PVC) and, for a `Service` of type `LoadBalancer`, a cloud LB or
MetalLB/kube-vip.

## 1. A single WAF node with Helm

```bash
helm install waf deploy/helm/hitechcloud-waf \
  --namespace hitechcloud-waf --create-namespace
```

By default the chart creates:

| Object | Content |
|---|---|
| Deployment `waf-hitechcloud-waf` | 1 `hcw-waf` pod, `Recreate` strategy (ReadWriteOnce PVC) |
| PVC `…-data` (2Gi) | `/var/lib/hcw-waf`: sites, certificates, accounts, ACME cache, events, access log |
| ConfigMap `…-config` | `waf.yaml` generated from `waf.config` in the values |
| Secret `…-auth` | `api-token`, `challenge-key`, `admin-password` (random, kept on `helm upgrade`) |
| Service `waf-hitechcloud-waf` | `LoadBalancer`, ports 80/443 for the sites, `externalTrafficPolicy: Local` |
| Service `…-console` | `ClusterIP` 9443: web console + management API (HTTPS) |
| Job `…-admin` | creates the first administrator account through the API (post-install/upgrade hook) |
| PodDisruptionBudget | `maxUnavailable: 1` |

`helm install` prints instructions (NOTES). In short:

```bash
# Open the console
kubectl -n hitechcloud-waf port-forward svc/waf-hitechcloud-waf-console 9443:9443
# then open https://127.0.0.1:9443/ (self-signed certificate)

# Password of the admin account (change it and enable 2FA right after logging in)
kubectl -n hitechcloud-waf get secret waf-hitechcloud-waf-auth \
  -o jsonpath='{.data.admin-password}' | base64 -d; echo

# API token (automation, Prometheus, logging in with the token)
kubectl -n hitechcloud-waf get secret waf-hitechcloud-waf-auth \
  -o jsonpath='{.data.api-token}' | base64 -d; echo

# Address that receives traffic: point the sites' DNS at this IP
kubectl -n hitechcloud-waf get svc waf-hitechcloud-waf
```

### Site ports

A site created in the console listens on the ports declared in the site
(usually `80` and `443_ssl`). Those ports must be listed in
`waf.ports[].containerPort`; the Service publishes them with
`waf.ports[].port`:

```yaml
waf:
  ports:
    - {name: http,  containerPort: 80,  port: 80}
    - {name: https, containerPort: 443, port: 443}
    - {name: alt,   containerPort: 8443, port: 8443}   # an extra port
service:
  type: LoadBalancer        # or NodePort / ClusterIP
  externalTrafficPolicy: Local
```

`externalTrafficPolicy: Local` keeps the client IP (needed for IP ACLs, rate
limits, GeoIP). If an L7 proxy (Ingress, CDN) sits in front of the WAF,
declare the proxy's IP range in `waf.config.trusted_proxies` so the engine
reads `X-Forwarded-For`.

### `waf.yaml` configuration

Every key in `waf.config` is written as is into `waf.yaml` (see
`waf/examples/waf.yaml` and [engine.md](engine.md)). The chart manages
`data_dir`, `api.*` and `challenge_secret_file` itself. The engine stops on an
invalid key, so check key names carefully. Example:

```yaml
waf:
  config:
    trusted_proxies: [10.0.0.0/8]
    acme: {enabled: true, email: noc@example.vn}
    geoip_db: /etc/hcw-waf/extra/country.mmdb
    alerts:
      kinds: [waf, rate_limit, bot]
      telegram:
        bot_token_file: /etc/hcw-waf/extra/telegram.token
        chat_id: "-1001234567890"
  extraVolumes:
    - name: extra
      secret: {secretName: waf-extra}     # country.mmdb, telegram.token
  extraVolumeMounts:
    - {name: extra, mountPath: /etc/hcw-waf/extra, readOnly: true}
```

Changing the ConfigMap restarts the pod (checksum annotation).

### Console through an Ingress

The console only speaks HTTPS, so the Ingress must call the backend over
HTTPS (the default annotation for ingress-nginx is already set):

```yaml
console:
  ingress:
    enabled: true
    className: nginx
    hosts:
      - host: waf-console.example.vn
        paths: [{path: /, pathType: Prefix}]
    tls:
      - {secretName: waf-console-tls, hosts: [waf-console.example.vn]}
waf:
  api:
    tls:
      generate: true    # console certificate signed by the chart CA instead of self-signed
```

Restrict who can reach the console with `waf.api.allow` (a list of
IPs/CIDRs). When `allow` is set, the probes switch to TCP (the kubelet would be
refused over HTTP) and `127.0.0.1/32` is added for the agent sidecar. Remember
to add the ingress controller's pod range to `allow`.

## 2. Pod security

- Runs as non-root (`uid 10002` for the engine, `10001` for
  controller/agent/DNS), `readOnlyRootFilesystem`,
  `seccompProfile: RuntimeDefault`, `allowPrivilegeEscalation: false`, and the
  ServiceAccount does not mount a token.
- Capabilities: `drop: [ALL]` and **always** keep `NET_BIND_SERVICE`. The
  `hcw-waf` binary in the image carries the `cap_net_bind_service` file
  capability; the kernel refuses to execute that binary if the capability is
  not in the bounding set (the pod fails with `operation not permitted` right
  at start-up). The non-root process gains no other privilege.
- To bind ports < 1024 without privilege escalation, the chart sets the
  pod-network-namespace sysctl `net.ipv4.ip_unprivileged_port_start` to the
  lowest port (for example `80`). This sysctl is in the "safe" group and is
  allowed by the **restricted** Pod Security Standard. The plain manifests
  label the namespace `pod-security.kubernetes.io/enforce: restricted`.
- Exception `waf.hostNetwork: true`: the sysctl above cannot be used in the
  node's network namespace, so the chart sets
  `allowPrivilegeEscalation: true` for the file capability to take effect.
  This mode does not meet the restricted level.
- Controller, agent and DNS need no capability at all. DNS listens on port
  5353 in the pod and the Service publishes port 53.

Health checks:

| Component | Probe |
|---|---|
| Engine | `GET https://:9443/api/open/health` (public, no token needed); TCP when `waf.api.allow` is set |
| Controller | `GET https://:7443/healthz` |
| DNS | TCP 5353 (DNS has no HTTP endpoint) |

The engine's `readiness` only passes once the site configuration has been
loaded.

## 3. Prometheus monitoring

`GET /api/open/metrics` needs the API token (Bearer) and is served on the
HTTPS console port. With the Prometheus Operator:

```yaml
metrics:
  serviceMonitor:
    enabled: true
    labels: {release: kube-prometheus-stack}   # the labels your Prometheus selects
```

The ServiceMonitor reads the token from the `…-auth` Secret (same namespace)
and scrapes each WAF pod. If the console certificate is signed by the chart
CA, that CA is used for verification; otherwise certificate verification is
skipped (`insecureSkipVerify`).

## 4. Scaling out to several pods

Each engine stores its own configuration in `data_dir`. For several WAF pods
to share one configuration, the chart runs:

- **primary** (`primary.enabled`): a separate engine with a PVC, where
  administrators edit sites and certificates; the console Ingress points
  here.
- **controller** (`controller.enabled`): reads the primary's configuration and
  distributes it to the nodes; dashboard on port 7443.
- **agent** (`agent.enabled`): a sidecar in every WAF pod that sends
  heartbeats, statistics and events to the controller and applies the
  configuration to the pod's engine.

Autoscaling example (complete in `deploy/helm/hitechcloud-waf/ci/full-values.yaml`):

```yaml
waf:
  persistence: {enabled: false}    # configuration comes from the primary
autoscaling: {enabled: true, minReplicas: 2, maxReplicas: 10}
primary: {enabled: true}
controller: {enabled: true}
agent:
  enabled: true
  region: hn
  pools: [web]
  ipv4: 203.0.113.10               # public IP of the LoadBalancer
```

The chart rejects combinations that cannot work, for example several pods
sharing a ReadWriteOnce PVC, several pods without an agent, or an agent
without a controller.

Notes:

- Console accounts and login sessions are stored per engine: administer on
  the primary. The admin Job only runs when the console is served by a single
  engine.
- Every pod shares the same `challenge-key`, so a visitor who has passed the
  anti-bot challenge does not have to solve it again when moved to another
  pod.
- `ulimit nofile` cannot be set in a pod; the containerd/CRI-O default is
  usually large enough (≥ 1048576).

### Edge nodes (DaemonSet + hostNetwork)

One WAF pod on every labelled node, listening directly on the node's IP and
keeping the client IP without a LoadBalancer:

```yaml
waf:
  kind: DaemonSet
  hostNetwork: true
  api:
    allow: [10.0.0.0/8]        # the console is open on every node: restricting it is mandatory
  persistence:
    enabled: true
    hostPath: /var/lib/hcw-waf # create it first: install -d -o 10002 -m 700 /var/lib/hcw-waf
  nodeSelector: {hitechcloud.vn/waf-edge: "true"}
agent:
  enabled: true
  id: __NODE_NAME__
  ipv4: __HOST_IP__
  probeURL: http://__HOST_IP__:80/
```

In the agent configuration, `__POD_NAME__`, `__POD_IP__`, `__HOST_IP__` and
`__NODE_NAME__` are replaced with the pod's real values by an init container
at start-up. Without hostNetwork and with `agent.ipv4` left empty, the agent
reports the pod IP: set the LoadBalancer's public IP so DNS answers
correctly.

### Controller and nodes/DNS outside the cluster

The chart generates its own CA (Secret `…-ca`, kept when the chart is
uninstalled) to sign the controller and console certificates. To let an
external agent or DNS machine connect:

```yaml
controller:
  enabled: true
  service: {type: LoadBalancer}
  tls:
    extraDNSNames: [ctl.waf.example.vn]
    extraIPs: [203.0.113.5]
```

```bash
kubectl -n hitechcloud-waf get secret waf-hitechcloud-waf-ca -o jsonpath='{.data.tls\.crt}' | base64 -d > ca.crt
kubectl -n hitechcloud-waf get secret waf-hitechcloud-waf-cluster -o jsonpath='{.data.node-token}' | base64 -d
kubectl -n hitechcloud-waf get secret waf-hitechcloud-waf-cluster -o jsonpath='{.data.dns-token}' | base64 -d
```

Then install the agent/DNS on the external machine following
[install.md](install.md). For external agents, prefer a one-time enrollment
token created on the controller dashboard (port 7443) over the shared
`node-token` (deprecated, see [cluster.md](cluster.md)). Conversely, WAF pods
can join a controller running elsewhere: `agent.controllerURL`,
`agent.controllerCASecret` (key `ca.crt`) and `agent.nodeTokenSecret` (key
`node-token`), see `ci/edge-daemonset-values.yaml`.

### Authoritative DNS

```yaml
dns:
  enabled: true
  zones:
    - name: waf.example.vn
      ns: [ns1.waf.example.vn, ns2.waf.example.vn]
      records:
        - {name: ns1, type: A, value: 203.0.113.53}
        - {name: ns2, type: A, value: 198.51.100.53}
        - {name: edge, pool: web, max_answers: 2, fail_open: true}
```

The `…-dns` Service (UDP+TCP 53, `LoadBalancer`) answers with the IPs of
healthy nodes. Declare the Service IP as the glue record of the name servers
at the domain registrar. The zone syntax is the same as in
`cluster/examples/dns.yaml`.

## 5. Secrets

The chart generates random values and keeps them on `helm upgrade` (through
`lookup`). With GitOps (Argo CD, Flux using `helm template`), `lookup` does
not run, so the values would change on every render: create the Secrets
beforehand and point the chart at them.

| Values | Keys in the Secret |
|---|---|
| `auth.existingSecret` | `api-token` (≥ 16 characters), `challenge-key` (≥ 32 characters), `admin-password` (10–72 characters, when `auth.admin.create`) |
| `cluster.existingSecret` | `admin-token`, `node-token`, `dns-token` |
| `cluster.ca.existingSecret` | the CA's `tls.crt`, `tls.key` |
| `controller.tls.existingSecret`, `waf.api.tls.existingSecret` | `tls.crt`, `tls.key` (signed by the CA above) |

The admin Job only creates the account when it does not exist yet and never
modifies an existing account. Changing `admin-password` after installation
does not change the password: change it in the console.

## 6. Plain manifests (without Helm)

`deploy/kubernetes/` holds one WAF node like the default chart, in the
`hitechcloud-waf` namespace, with credentials taken from a Secret you create
yourself:

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl -n hitechcloud-waf create secret generic hitechcloud-waf-auth \
  --from-literal=api-token="$(openssl rand -hex 32)" \
  --from-literal=challenge-key="$(openssl rand -hex 32)" \
  --from-literal=admin-password="$(openssl rand -hex 12)"
kubectl apply -k deploy/kubernetes

kubectl -n hitechcloud-waf rollout status deploy/hitechcloud-waf
kubectl -n hitechcloud-waf port-forward svc/hitechcloud-waf-console 9443:9443
```

Log in as `admin` with the password from the Secret. The
`hitechcloud-waf-admin` Job deletes itself after 10 minutes; running
`kubectl apply -k` again recreates the Job, which does nothing if the account
already exists.

To change the configuration (StorageClass, Service type, ports…), edit
`deploy/kubernetes/values.yaml` and regenerate with
`deploy/kubernetes/render.sh` (needs Helm), or use kustomize patches. Do not
edit `hitechcloud-waf.yaml` by hand: CI checks that it matches the chart.

## 7. Upgrading, uninstalling

```bash
helm upgrade waf deploy/helm/hitechcloud-waf -n hitechcloud-waf --reuse-values \
  --set image.tag=<sha> --set clusterImage.tag=<sha>
helm uninstall waf -n hitechcloud-waf
```

The data PVC and the CA Secret carry `helm.sh/resource-policy: keep`, so they
are not deleted when the chart is uninstalled (a reinstall reuses them). To
delete them for good:

```bash
kubectl -n hitechcloud-waf delete pvc -l app.kubernetes.io/instance=waf
kubectl -n hitechcloud-waf delete secret waf-hitechcloud-waf-ca
```

## 8. Checking the chart

```bash
helm lint deploy/helm/hitechcloud-waf --strict
helm lint deploy/helm/hitechcloud-waf --strict -f deploy/helm/hitechcloud-waf/ci/full-values.yaml
helm template waf deploy/helm/hitechcloud-waf -f deploy/helm/hitechcloud-waf/ci/full-values.yaml
deploy/kubernetes/render.sh --check
```

The `helm` job in `.github/workflows/ci.yml` runs these commands, validates
the manifests with kubeconform and makes sure `deploy/kubernetes/` matches the
chart.
