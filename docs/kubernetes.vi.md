# Triển khai HiTechCloud WAF trên Kubernetes

Có hai cách:

- **Helm chart** `deploy/helm/hitechcloud-waf/`: đầy đủ tuỳ chọn, từ một
  node WAF đơn lẻ đến cluster nhiều pod có controller, agent và DNS.
- **Manifest thuần** `deploy/kubernetes/`: một node WAF, cài bằng
  `kubectl apply -k`, không cần Helm. File được sinh từ chart nên luôn khớp
  với chart.

Image (CI đẩy lên GHCR mỗi lần merge vào `main`, tag `latest` và SHA của
commit; nên ghim SHA khi chạy thật):

| Image | Dùng cho |
|---|---|
| `ghcr.io/hitechcloud-vietnam/hitechcloud-waf` | engine `hcw-waf` (proxy, WAF, console) |
| `ghcr.io/hitechcloud-vietnam/hitechcloud-waf-cluster` | `hcw controller` / `agent` / `dns` |

Nếu package trên GHCR để private, tạo secret kéo image rồi khai báo
`imagePullSecrets`:

```bash
kubectl -n hitechcloud-waf create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io --docker-username=<user> --docker-password=<token đọc package>
# values: imagePullSecrets: [{name: ghcr-pull}]
```

Yêu cầu: Kubernetes ≥ 1.25, Helm 3, một StorageClass mặc định (cho PVC dữ
liệu) và nếu dùng `Service` kiểu `LoadBalancer` thì cần cloud LB hoặc
MetalLB/kube-vip.

## 1. Một node WAF bằng Helm

```bash
helm install waf deploy/helm/hitechcloud-waf \
  --namespace hitechcloud-waf --create-namespace
```

Mặc định chart tạo:

| Đối tượng | Nội dung |
|---|---|
| Deployment `waf-hitechcloud-waf` | 1 pod `hcw-waf`, chiến lược `Recreate` (PVC ReadWriteOnce) |
| PVC `…-data` (2Gi) | `/var/lib/hcw-waf`: site, chứng chỉ, tài khoản, cache ACME, sự kiện, access log |
| ConfigMap `…-config` | `waf.yaml` sinh từ `waf.config` trong values |
| Secret `…-auth` | `api-token`, `challenge-key`, `admin-password` (ngẫu nhiên, giữ nguyên khi `helm upgrade`) |
| Service `waf-hitechcloud-waf` | `LoadBalancer`, cổng 80/443 cho site, `externalTrafficPolicy: Local` |
| Service `…-console` | `ClusterIP` 9443: console web + API quản trị (HTTPS) |
| Job `…-admin` | tạo tài khoản quản trị đầu tiên qua API (hook post-install/upgrade) |
| PodDisruptionBudget | `maxUnavailable: 1` |

`helm install` in ra hướng dẫn (NOTES). Tóm tắt:

```bash
# Mở console
kubectl -n hitechcloud-waf port-forward svc/waf-hitechcloud-waf-console 9443:9443
# rồi mở https://127.0.0.1:9443/ (chứng chỉ tự ký)

# Mật khẩu tài khoản admin (đổi mật khẩu và bật 2FA ngay sau khi đăng nhập)
kubectl -n hitechcloud-waf get secret waf-hitechcloud-waf-auth \
  -o jsonpath='{.data.admin-password}' | base64 -d; echo

# API token (tự động hoá, Prometheus, đăng nhập bằng token)
kubectl -n hitechcloud-waf get secret waf-hitechcloud-waf-auth \
  -o jsonpath='{.data.api-token}' | base64 -d; echo

# Địa chỉ nhận traffic: trỏ DNS các site về IP này
kubectl -n hitechcloud-waf get svc waf-hitechcloud-waf
```

### Cổng của site

Site tạo trên console nghe ở cổng khai báo trong site (thường `80` và
`443_ssl`). Cổng đó phải nằm trong `waf.ports[].containerPort`; Service
publish ra ngoài bằng `waf.ports[].port`:

```yaml
waf:
  ports:
    - {name: http,  containerPort: 80,  port: 80}
    - {name: https, containerPort: 443, port: 443}
    - {name: alt,   containerPort: 8443, port: 8443}   # thêm cổng khác
service:
  type: LoadBalancer        # hoặc NodePort / ClusterIP
  externalTrafficPolicy: Local
```

`externalTrafficPolicy: Local` giữ nguyên IP client (cần cho ACL IP, rate
limit, GeoIP). Nếu đặt trước WAF một L7 proxy (Ingress, CDN), khai báo dải
IP của proxy ở `waf.config.trusted_proxies` để engine đọc `X-Forwarded-For`.

### Cấu hình `waf.yaml`

Mọi khoá trong `waf.config` được ghi nguyên vào `waf.yaml` (xem
`waf/examples/waf.yaml` và [engine.vi.md](engine.vi.md)). Chart tự quản lý
`data_dir`, `api.*` và `challenge_secret_file`. Engine dừng nếu gặp khoá
không hợp lệ, nên kiểm tra kỹ tên khoá. Ví dụ:

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

Đổi ConfigMap sẽ làm pod khởi động lại (annotation checksum).

### Console qua Ingress

Console chỉ nói HTTPS, nên Ingress phải gọi backend bằng HTTPS (annotation
mặc định cho ingress-nginx đã có sẵn):

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
      generate: true    # chứng chỉ console do CA của chart ký thay cho tự ký
```

Hạn chế ai được vào console bằng `waf.api.allow` (danh sách IP/CIDR). Khi
đặt `allow`, probe tự chuyển sang TCP (kubelet sẽ bị từ chối nếu gọi HTTP)
và `127.0.0.1/32` được thêm cho agent sidecar. Nhớ thêm dải pod của ingress
controller vào `allow`.

## 2. Bảo mật pod

- Chạy non-root (`uid 10002` cho engine, `10001` cho controller/agent/DNS),
  `readOnlyRootFilesystem`, `seccompProfile: RuntimeDefault`,
  `allowPrivilegeEscalation: false`, ServiceAccount không mount token.
- Capability: `drop: [ALL]` và **luôn** giữ `NET_BIND_SERVICE`. Binary
  `hcw-waf` trong image mang file capability `cap_net_bind_service`; kernel
  từ chối chạy binary đó nếu capability không có trong bounding set (pod sẽ
  lỗi `operation not permitted` ngay khi khởi động). Tiến trình non-root
  không có thêm quyền nào khác.
- Để bind cổng < 1024 mà không cần leo quyền, chart đặt sysctl theo
  namespace mạng của pod `net.ipv4.ip_unprivileged_port_start` = cổng thấp
  nhất (ví dụ `80`). Sysctl này thuộc nhóm "safe" và được Pod Security
  Standard **restricted** cho phép. Manifest thuần gắn nhãn namespace
  `pod-security.kubernetes.io/enforce: restricted`.
- Ngoại lệ `waf.hostNetwork: true`: sysctl trên không dùng được trong
  namespace mạng của node, nên chart bật `allowPrivilegeEscalation: true`
  để file capability có hiệu lực. Chế độ này không đạt mức restricted.
- Controller, agent và DNS không cần capability nào. DNS nghe cổng 5353 trong
  pod, Service publish cổng 53.

Health check:

| Thành phần | Probe |
|---|---|
| Engine | `GET https://:9443/api/open/health` (công khai, không cần token); TCP khi có `waf.api.allow` |
| Controller | `GET https://:7443/healthz` |
| DNS | TCP 5353 (DNS không có endpoint HTTP) |

`readiness` của engine chỉ đạt sau khi cấu hình site đã được nạp.

## 3. Giám sát Prometheus

`GET /api/open/metrics` cần API token (Bearer) và chạy trên cổng console
HTTPS. Với Prometheus Operator:

```yaml
metrics:
  serviceMonitor:
    enabled: true
    labels: {release: kube-prometheus-stack}   # nhãn Prometheus của bạn chọn
```

ServiceMonitor đọc token từ Secret `…-auth` (cùng namespace), scrape từng pod
WAF. Nếu chứng chỉ console do CA của chart ký thì CA được dùng để xác thực,
ngược lại bỏ qua kiểm tra chứng chỉ (`insecureSkipVerify`).

## 4. Mở rộng nhiều pod

Mỗi engine lưu cấu hình riêng trong `data_dir`. Để nhiều pod WAF dùng chung
cấu hình, chart chạy:

- **primary** (`primary.enabled`): một engine riêng, có PVC, là nơi quản trị
  viên sửa site và chứng chỉ; Ingress console trỏ về đây.
- **controller** (`controller.enabled`): đọc cấu hình của primary và phân
  phối cho các node; dashboard ở cổng 7443.
- **agent** (`agent.enabled`): sidecar trong mỗi pod WAF, gửi heartbeat,
  thống kê, sự kiện về controller và áp cấu hình vào engine của pod.

Ví dụ autoscale (đầy đủ ở `deploy/helm/hitechcloud-waf/ci/full-values.yaml`):

```yaml
waf:
  persistence: {enabled: false}    # cấu hình đến từ primary
autoscaling: {enabled: true, minReplicas: 2, maxReplicas: 10}
primary: {enabled: true}
controller: {enabled: true}
agent:
  enabled: true
  region: hn
  pools: [web]
  ipv4: 203.0.113.10               # IP public của LoadBalancer
```

Chart chặn các tổ hợp không chạy được, ví dụ nhiều pod dùng chung PVC
ReadWriteOnce, nhiều pod mà không có agent, agent không có controller.

Lưu ý:

- Tài khoản console và phiên đăng nhập lưu theo từng engine: hãy quản trị
  trên primary. Job tạo admin chỉ chạy khi console do một engine phục vụ.
- Mọi pod dùng chung `challenge-key`, nên khách đã qua anti-bot challenge
  không phải giải lại khi bị chuyển sang pod khác.
- `ulimit nofile` không đặt được trong pod; containerd/CRI-O mặc định thường
  đã đủ lớn (≥ 1048576).

### Node biên (DaemonSet + hostNetwork)

Một pod WAF trên mỗi node được gắn nhãn, nghe trực tiếp trên IP của node, giữ
IP client mà không cần LoadBalancer:

```yaml
waf:
  kind: DaemonSet
  hostNetwork: true
  api:
    allow: [10.0.0.0/8]        # console mở trên mọi node: bắt buộc giới hạn
  persistence:
    enabled: true
    hostPath: /var/lib/hcw-waf # tạo trước: install -d -o 10002 -m 700 /var/lib/hcw-waf
  nodeSelector: {hitechcloud.vn/waf-edge: "true"}
agent:
  enabled: true
  id: __NODE_NAME__
  ipv4: __HOST_IP__
  probeURL: http://__HOST_IP__:80/
```

Trong cấu hình agent, `__POD_NAME__`, `__POD_IP__`, `__HOST_IP__`,
`__NODE_NAME__` được init container thay bằng giá trị thật của pod khi khởi
động. Khi không dùng hostNetwork mà để trống `agent.ipv4`, agent sẽ báo IP
pod: hãy đặt IP public của LoadBalancer để DNS trả lời đúng.

### Controller và node/DNS ngoài cluster

Chart sinh một CA riêng (Secret `…-ca`, giữ lại khi gỡ chart) để ký chứng chỉ
controller và console. Để agent hay máy DNS bên ngoài kết nối:

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

Rồi cài agent/DNS trên máy ngoài theo [install.vi.md](install.vi.md). Ngược
lại, pod WAF có thể tham gia một controller đặt ở nơi khác:
`agent.controllerURL`, `agent.controllerCASecret` (khoá `ca.crt`) và
`agent.nodeTokenSecret` (khoá `node-token`), xem
`ci/edge-daemonset-values.yaml`.

### DNS authoritative

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

Service `…-dns` (UDP+TCP 53, `LoadBalancer`) trả lời bằng IP các node khỏe.
Khai báo IP của Service làm glue record cho NS ở nhà đăng ký tên miền. Cú
pháp zone giống `cluster/examples/dns.yaml`.

## 5. Secret

Chart sinh giá trị ngẫu nhiên và giữ lại khi `helm upgrade` (qua `lookup`).
Với GitOps (Argo CD, Flux dùng `helm template`), `lookup` không chạy nên giá
trị sẽ đổi mỗi lần render: hãy tạo Secret trước và trỏ chart vào đó.

| Values | Khoá trong Secret |
|---|---|
| `auth.existingSecret` | `api-token` (≥ 16 ký tự), `challenge-key` (≥ 32 ký tự), `admin-password` (10–72 ký tự, khi `auth.admin.create`) |
| `cluster.existingSecret` | `admin-token`, `node-token`, `dns-token` |
| `cluster.ca.existingSecret` | `tls.crt`, `tls.key` của CA |
| `controller.tls.existingSecret`, `waf.api.tls.existingSecret` | `tls.crt`, `tls.key` (do CA trên ký) |

Job tạo admin chỉ tạo tài khoản khi chưa tồn tại, không bao giờ sửa tài khoản
đã có. Đổi `admin-password` sau khi cài không đổi mật khẩu: hãy đổi trên
console.

## 6. Manifest thuần (không dùng Helm)

`deploy/kubernetes/` chứa một node WAF giống chart mặc định, namespace
`hitechcloud-waf`, credential lấy từ Secret bạn tự tạo:

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

Đăng nhập `admin` với mật khẩu trong Secret. Job `hitechcloud-waf-admin` tự
xoá sau 10 phút; chạy lại `kubectl apply -k` sẽ tạo lại Job, Job bỏ qua nếu
tài khoản đã có.

Muốn đổi cấu hình (StorageClass, kiểu Service, cổng…), sửa
`deploy/kubernetes/values.yaml` rồi sinh lại bằng
`deploy/kubernetes/render.sh` (cần Helm), hoặc dùng patch của kustomize. Không
sửa tay `hitechcloud-waf.yaml`: CI kiểm tra file này khớp với chart.

## 7. Nâng cấp, gỡ bỏ

```bash
helm upgrade waf deploy/helm/hitechcloud-waf -n hitechcloud-waf --reuse-values \
  --set image.tag=<sha> --set clusterImage.tag=<sha>
helm uninstall waf -n hitechcloud-waf
```

PVC dữ liệu và Secret CA có `helm.sh/resource-policy: keep` nên không bị xoá
khi gỡ chart (cài lại sẽ dùng lại). Xoá hẳn:

```bash
kubectl -n hitechcloud-waf delete pvc -l app.kubernetes.io/instance=waf
kubectl -n hitechcloud-waf delete secret waf-hitechcloud-waf-ca
```

## 8. Kiểm tra chart

```bash
helm lint deploy/helm/hitechcloud-waf --strict
helm lint deploy/helm/hitechcloud-waf --strict -f deploy/helm/hitechcloud-waf/ci/full-values.yaml
helm template waf deploy/helm/hitechcloud-waf -f deploy/helm/hitechcloud-waf/ci/full-values.yaml
deploy/kubernetes/render.sh --check
```

Job `helm` trong `.github/workflows/ci.yml` chạy các lệnh trên, kiểm tra
manifest bằng kubeconform và đảm bảo `deploy/kubernetes/` khớp với chart.
