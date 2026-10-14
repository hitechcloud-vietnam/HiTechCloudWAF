# Hướng dẫn triển khai HiTechCloud WAF (chi tiết)

Tài liệu này đi từ chuẩn bị máy chủ tới vận hành production: một node đơn,
Docker, Kubernetes, cluster nhiều node có DNS, bảo mật, giám sát, sao lưu,
nâng cấp và xử lý sự cố. Các lệnh dùng bản phát hành trên GitHub
(`releases/latest`) và đã được chạy thử với `scripts/install.sh`.

Tài liệu liên quan: [engine.vi.md](engine.vi.md) (mọi tuỳ chọn của site),
[cluster.vi.md](cluster.vi.md) (kiến trúc cluster, DNS),
[kubernetes.vi.md](kubernetes.vi.md) (Helm), [api/README.md](api/README.md)
(API), [../ctl/README.md](../ctl/README.md) (`hcwctl`).

---

## Mục lục

1. [Chọn mô hình triển khai](#1-chọn-mô-hình-triển-khai)
2. [Yêu cầu hệ thống](#2-yêu-cầu-hệ-thống)
3. [Cổng mạng và tường lửa](#3-cổng-mạng-và-tường-lửa)
4. [Mô hình A: một node WAF (systemd)](#4-mô-hình-a-một-node-waf-systemd)
5. [Đưa website đầu tiên vào bảo vệ](#5-đưa-website-đầu-tiên-vào-bảo-vệ)
6. [HTTPS cho website](#6-https-cho-website)
7. [Mô hình B: Docker](#7-mô-hình-b-docker)
8. [Mô hình C: Kubernetes](#8-mô-hình-c-kubernetes)
9. [Mô hình D: cluster nhiều node + DNS](#9-mô-hình-d-cluster-nhiều-node--dns)
10. [WAF đứng sau load balancer / CDN](#10-waf-đứng-sau-load-balancer--cdn)
11. [Cấu hình nâng cao của node](#11-cấu-hình-nâng-cao-của-node)
12. [Danh sách kiểm tra bảo mật](#12-danh-sách-kiểm-tra-bảo-mật)
13. [Giám sát, log và cảnh báo](#13-giám-sát-log-và-cảnh-báo)
14. [Sao lưu và khôi phục](#14-sao-lưu-và-khôi-phục)
15. [Nâng cấp và quay lại phiên bản cũ](#15-nâng-cấp-và-quay-lại-phiên-bản-cũ)
16. [Hiệu năng và định cỡ](#16-hiệu-năng-và-định-cỡ)
17. [Xử lý sự cố](#17-xử-lý-sự-cố)
18. [Gỡ cài đặt](#18-gỡ-cài-đặt)
19. [Phụ lục: đường dẫn, file và dịch vụ](#19-phụ-lục-đường-dẫn-file-và-dịch-vụ)

---

## 1. Chọn mô hình triển khai

| Mô hình | Khi nào dùng | Thành phần |
|---|---|---|
| **A. Một node (systemd)** | Một máy chủ bảo vệ một hoặc nhiều website; bắt đầu từ đây | `hcw-waf` |
| **B. Docker** | Hạ tầng đã chuẩn hoá bằng Docker | image `hitechcloud-waf` (+ `hitechcloud-waf-cluster`) |
| **C. Kubernetes** | Cụm K8s, Ingress, Prometheus Operator | Helm chart `deploy/helm/hitechcloud-waf` |
| **D. Cluster + DNS** | Nhiều node ở nhiều nơi, chịu lỗi, định tuyến theo vùng/quốc gia | `hcw-waf` trên mọi node, `hcw controller`, `hcw agent`, `hcw dns` |

Các thành phần:

- **`hcw-waf`** – engine: reverse proxy + OWASP Coraza + CRS v4, console web và
  API quản trị (cổng 9443). Mỗi node WAF chạy một tiến trình.
- **`hcw controller`** – control plane của cluster: theo dõi sức khỏe node,
  đồng bộ cấu hình từ node *primary* sang mọi node, cấp danh sách IP khỏe cho
  DNS, dashboard (cổng 7443).
- **`hcw agent`** – chạy cạnh mỗi `hcw-waf` trong cluster: gửi heartbeat,
  thống kê, sự kiện tấn công; áp cấu hình đồng bộ vào engine cục bộ.
- **`hcw dns`** – DNS authoritative: chỉ trả IP node khỏe, ưu tiên vùng/quốc
  gia, bản ghi tĩnh.
- **`hcwctl`** – công cụ dòng lệnh quản trị (Linux/macOS/Windows).

```
                Khách truy cập
                      │  (DNS: shop.vn CNAME edge.waf.example.vn)
          ┌───────────┴────────────┐
   ns1/ns2 (hcw dns) ── trả IP node khỏe gần khách nhất
          │
   ┌──────┴──────┐   ┌─────────────┐   ┌─────────────┐
   │ node HN     │   │ node HCM    │   │ node SG     │   hcw-waf + hcw agent
   │ 80/443      │   │ 80/443      │   │ 80/443      │──► upstream (server gốc)
   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
          └──── heartbeat / sync (HTTPS 7443) ─┘
                      │
            controller + node primary (console 9443, dashboard 7443)
```

---

## 2. Yêu cầu hệ thống

**Hệ điều hành:** Linux 64-bit có systemd (Ubuntu 22.04/24.04, Debian 12,
Rocky/Alma 9…), kiến trúc **amd64** hoặc **arm64**. Binary tĩnh, không cần
thư viện ngoài. Installer cần `bash`, `curl`, `sha256sum`, `gunzip`, `openssl`
(chỉ vai trò controller), `python3` (chỉ khi tải từ repo private).

**Cấu hình gợi ý cho một node WAF** (xem chi tiết ở [mục 16](#16-hiệu-năng-và-định-cỡ)):

| Lưu lượng có kiểm tra WAF | vCPU | RAM | Đĩa |
|---|---|---|---|
| Thử nghiệm / site nhỏ (< 100 req/s) | 2 | 2 GB | 20 GB |
| Vừa (khoảng 300–600 req/s) | 4 | 4 GB | 40 GB |
| Lớn (> 1000 req/s) | 8+ hoặc nhiều node | 8 GB+ | 80 GB+ |

Controller và DNS rất nhẹ: 1 vCPU, 1 GB RAM là đủ. Nên đặt **ít nhất 2 máy
DNS** ở hai nơi khác nhau.

**Đồng hồ:** bật đồng bộ giờ (`timedatectl set-ntp true`). Xác thực 2 lớp
(TOTP), token đăng ký node và chứng chỉ TLS đều phụ thuộc giờ hệ thống.

**Tên miền (cho cluster):** một zone riêng cho WAF, ví dụ
`waf.example.vn`, được ủy quyền (NS) về các máy DNS của bạn.

---

## 3. Cổng mạng và tường lửa

| Cổng | Giao thức | Thành phần | Ai cần truy cập |
|---|---|---|---|
| 80, 443 (và cổng site khác) | TCP | `hcw-waf` | Internet (khách truy cập) |
| 9443 | TCP/HTTPS | console + API của `hcw-waf` | Chỉ quản trị viên, agent cục bộ, controller (nếu node là primary), Prometheus |
| 7443 | TCP/HTTPS | `hcw controller` | Agent trên các node, máy DNS, quản trị viên |
| 53 | UDP + TCP | `hcw dns` | Internet (resolver) |

Chiều đi ra:

- Node (agent) → controller: TCP 7443.
- Controller → node: HTTP tới `probe_url` (mặc định `http://<ipv4 node>:80/`).
- DNS → controller: TCP 7443.
- Node → upstream (server gốc): cổng của upstream.
- Node → Internet (tuỳ chọn): Let's Encrypt, tải threat intelligence, GeoIP.

Ví dụ với **ufw** (Ubuntu) trên một node WAF có console chỉ cho dải quản trị
`203.0.113.0/24`:

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow from 203.0.113.0/24 to any port 9443 proto tcp
sudo ufw enable
```

Với **firewalld** (Rocky/Alma):

```bash
sudo firewall-cmd --permanent --add-service=http --add-service=https
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=203.0.113.0/24 port port=9443 protocol=tcp accept'
sudo firewall-cmd --reload
```

Máy DNS: mở `53/udp` và `53/tcp`. Máy controller: mở `7443/tcp` cho IP các
node, máy DNS và quản trị viên.

> Ngoài tường lửa hệ điều hành, `hcw-waf` còn có `api.allow` (danh sách IP được
> vào console/API) – nên dùng cả hai.

---

## 4. Mô hình A: một node WAF (systemd)

### 4.1. Cài đặt

```bash
curl -fsSLO https://github.com/hitechcloud-vietnam/HiTechCloudWAF/releases/latest/download/install.sh
sudo bash install.sh node
```

Tuỳ chọn:

| Tuỳ chọn | Ý nghĩa |
|---|---|
| `--version v0.5.0` | Cài đúng phiên bản (mặc định: mới nhất) |
| `--public-console 203.0.113.0/24` | Console nghe `0.0.0.0:9443` và chỉ cho dải IP này (`api.allow`) |
| `--geoip` | Tải cơ sở dữ liệu quốc gia DB-IP Lite (miễn phí, CC BY 4.0) cho chặn theo quốc gia |
| `--binary ./hcw-waf` | Dùng binary có sẵn thay vì tải về |
| `--no-start` | Chỉ ghi file, không khởi động |

Repo private: thêm `GITHUB_TOKEN=<token đọc được repo>` trước `bash install.sh`
(token được truyền qua file header tạm, không lộ trên dòng lệnh).

Installer sẽ:

1. Tải `hcw-waf-linux-<arch>` và **kiểm tra SHA256** với `SHA256SUMS` của
   release (sai thì dừng).
2. Tạo user hệ thống `hcwwaf` (không shell, không home).
3. Sinh API token ngẫu nhiên 64 ký tự hex: `/etc/hcw-waf/api.token` (quyền 600).
4. Ghi `/etc/hcw-waf/waf.yaml` (chỉ khi chưa có – cập nhật không ghi đè).
5. Tạo service `hcw-waf` với hardening: chạy user thường, chỉ giữ quyền
   `CAP_NET_BIND_SERVICE`, `NoNewPrivileges`, `ProtectSystem=strict`, chỉ
   ghi được `/var/lib/hcw-waf`.

### 4.2. Kiểm tra

```bash
systemctl status hcw-waf
journalctl -u hcw-waf -n 50 --no-pager     # log JSON; có dòng "engine ready"
curl -sk https://127.0.0.1:9443/api/open/health   # {"data":"ok",...}
hcw-waf -version
```

### 4.3. Vào console

Console mặc định chỉ nghe `127.0.0.1:9443`. Từ máy của bạn:

```bash
ssh -L 9443:127.0.0.1:9443 root@<ip-server>
# mở https://127.0.0.1:9443/  (chứng chỉ tự ký – chấp nhận cảnh báo, hoặc thay chứng chỉ ở mục 11.1)
```

Lần đầu đăng nhập bằng **API token**: bấm *Dùng API token* rồi dán nội dung
`sudo cat /etc/hcw-waf/api.token`.

Ngay sau đó:

1. **Người dùng → Thêm**: tạo tài khoản vai trò `admin` cho từng người (mật
   khẩu ≥ 10 ký tự). Vai trò `viewer` chỉ xem, không thấy private key và
   không sửa được gì.
2. Đăng xuất, đăng nhập bằng tài khoản vừa tạo, vào **Tài khoản → Bật xác thực
   2 lớp** (Google/Microsoft Authenticator, Authy).
3. Cất API token vào nơi an toàn; dùng nó cho tự động hoá (`hcwctl`, CI,
   Prometheus), không dùng hằng ngày.

Đổi ngôn ngữ console: nút **VI/EN** ở góc trái dưới.

### 4.4. Cài `hcwctl` (tuỳ chọn)

```bash
sudo curl -fsSLo /usr/local/bin/hcwctl \
  https://github.com/hitechcloud-vietnam/HiTechCloudWAF/releases/latest/download/hcwctl-linux-amd64
sudo chmod +x /usr/local/bin/hcwctl
sudo hcwctl login --url https://127.0.0.1:9443 --token-file /etc/hcw-waf/api.token \
  --ca /var/lib/hcw-waf/api.crt
hcwctl sites list
```

Bản macOS: `hcwctl-darwin-arm64` / `hcwctl-darwin-amd64`; Windows:
`hcwctl-windows-amd64.exe`. `hcwctl` luôn kiểm tra TLS: dùng `--ca` với
chứng chỉ của node (`/var/lib/hcw-waf/api.crt` khi tự ký); `--insecure` chỉ
được phép với `127.0.0.1`/`localhost`.

---

## 5. Đưa website đầu tiên vào bảo vệ

Giả sử website `shop.example.vn` đang chạy ở server gốc `10.0.0.10:8080`.

### 5.1. Tạo ứng dụng

**Cách 1 – console:** *Ứng dụng → Thêm ứng dụng*:

- Tên miền: `shop.example.vn` (mỗi dòng một tên; hỗ trợ `*.example.vn`).
- Cổng: `80` (thêm `443_ssl` khi có chứng chỉ – mục 6).
- Upstream: `http://10.0.0.10:8080` (nhiều dòng = cân bằng tải).
- Chế độ: **Giám sát** trong vài ngày đầu (xem mục 5.3).

**Cách 2 – `hcwctl`:**

```bash
cat > shop.json <<'EOF'
{
  "name": "shop",
  "server_names": ["shop.example.vn", "www.shop.example.vn"],
  "ports": ["80"],
  "upstreams": ["http://10.0.0.10:8080"],
  "mode": "monitor",
  "rate_limit": {"requests": 300, "window_sec": 60, "block_sec": 300},
  "health_check": {"path": "/", "interval_sec": 10, "timeout_sec": 3, "unhealthy": 3, "healthy": 2}
}
EOF
hcwctl sites create -f shop.json
```

**Cách 3 – API (curl):**

```bash
TOKEN=$(sudo cat /etc/hcw-waf/api.token)
curl -s --cacert /var/lib/hcw-waf/api.crt -H "X-HCW-API-TOKEN: $TOKEN" \
  -H 'Content-Type: application/json' -d @shop.json https://127.0.0.1:9443/api/open/site
```

Mẫu đầy đủ (cân bằng tải, sticky, header…): `waf/examples/site.json`. Mọi
trường được mô tả trong [engine.vi.md](engine.vi.md).

### 5.2. Thử trước khi đổi DNS

```bash
# Request bình thường → 200 từ server gốc
curl -sI -H 'Host: shop.example.vn' http://<ip-node>/
# Tấn công SQLi → ở chế độ block trả 403 kèm Event ID; ở chế độ giám sát vẫn 200 nhưng có sự kiện
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: shop.example.vn' \
  "http://<ip-node>/?id=1%27%20UNION%20SELECT%20password%20FROM%20users--"
```

Xem kết quả ở **Sự kiện tấn công** trên console hoặc `hcwctl events`.

### 5.3. Trỏ DNS và chuyển sang chế độ chặn

1. Hạ TTL bản ghi DNS của website xuống 300 giây trước một ngày.
2. Đổi bản ghi A của `shop.example.vn` về IP node WAF (cluster: CNAME về
   `edge.waf.example.vn`, mục 9).
3. Để chế độ **Giám sát** 3–7 ngày, xem trang Sự kiện: lọc theo *Rule* để tìm
   rule bị kích hoạt bởi request hợp lệ (chặn nhầm). Với mỗi rule chặn nhầm:
   bấm *Báo chặn nhầm* trên sự kiện, hoặc thêm ID vào **Tắt rule (ID)**, hoặc
   tạo rule đường dẫn `skip_waf` cho đúng đường dẫn đó (ví dụ `/api/upload`).
4. Chuyển chế độ sang **Chặn**: `hcwctl sites set-mode <id> block`.
5. Bật thêm tuỳ ý: anti-bot challenge, rate limit theo đường dẫn (`/login`),
   chặn quốc gia, threat intelligence, cache tĩnh, gzip.

> Server gốc nên **chỉ nhận kết nối từ IP các node WAF** (tường lửa ở server
> gốc), nếu không kẻ tấn công có thể đi vòng qua WAF bằng IP gốc.

---

## 6. HTTPS cho website

Cổng HTTPS của site ghi dạng `443_ssl`. Có hai cách cấp chứng chỉ:

### 6.1. Tải chứng chỉ có sẵn

Console *Chứng chỉ → Thêm* (dán fullchain + private key), hoặc:

```bash
hcwctl certs add --crt fullchain.pem --key privkey.pem
hcwctl certs list            # lấy ID
```

Sửa site: cổng `["80", "443_ssl"]`, chọn chứng chỉ, bật **Chuyển hướng HTTP →
HTTPS** và **HSTS** khi đã chắc chắn chạy ổn. Một node phục vụ được nhiều
chứng chỉ theo SNI.

### 6.2. Let's Encrypt tự động

1. Trong `/etc/hcw-waf/waf.yaml`:

   ```yaml
   acme:
     enabled: true
     email: admin@example.vn
     # Thử nghiệm trước với staging để không bị giới hạn tần suất:
     # directory_url: https://acme-staging-v02.api.letsencrypt.org/directory
   ```

2. `sudo systemctl restart hcw-waf`
3. Site: bật **Tự động cấp chứng chỉ Let's Encrypt** (`auto_tls: true`), cổng
   `["80", "443_ssl"]`. Tên miền phải trỏ về node và cổng 80 (HTTP-01) hoặc 443
   (TLS-ALPN) mở từ Internet. Không hỗ trợ tên wildcard với ACME.

Chứng chỉ được lưu trong `/var/lib/hcw-waf` và tự gia hạn.

> Trong cluster, chứng chỉ Let's Encrypt cấp riêng trên từng node; với nhiều
> node, nên dùng chứng chỉ tải lên ở node primary (được đồng bộ sang mọi node).

---

## 7. Mô hình B: Docker

Image trên GHCR (CI đẩy mỗi lần merge vào `main`, tag `latest` và SHA commit):

- `ghcr.io/hitechcloud-vietnam/hitechcloud-waf` – engine, chạy user UID 10002.
- `ghcr.io/hitechcloud-vietnam/hitechcloud-waf-cluster` – `hcw`
  (controller/agent/dns), UID 10001.

Package private: `echo <PAT> | docker login ghcr.io -u <user> --password-stdin`.

### 7.1. Một node

```bash
sudo mkdir -p /etc/hcw-waf /var/lib/hcw-waf
# token API (≥ 16 ký tự)
openssl rand -hex 32 | sudo tee /etc/hcw-waf/api.token >/dev/null
sudo tee /etc/hcw-waf/waf.yaml >/dev/null <<'EOF'
data_dir: /var/lib/hcw-waf
api:
  listen: 127.0.0.1:9443
  token_file: /etc/hcw-waf/api.token
events_kept: 5000
events_file: /var/lib/hcw-waf/events.jsonl
brand: {name: HiTechCloud WAF, color: "#1D4ED8"}
EOF
# quyền cho user trong container
sudo chown -R 10002 /etc/hcw-waf /var/lib/hcw-waf && sudo chmod 600 /etc/hcw-waf/api.token

git clone https://github.com/hitechcloud-vietnam/HiTechCloudWAF.git && cd HiTechCloudWAF/waf/deploy
docker compose up -d hcw-waf          # chỉ engine; bỏ "hcw-waf" để chạy cả agent
docker compose logs -f hcw-waf
```

`compose.yaml` dùng `network_mode: host` (giữ IP thật của khách, phục vụ trực
tiếp các cổng site), `read_only`, bỏ mọi capability trừ `NET_BIND_SERVICE`.
Đổi đường dẫn bằng biến `HCW_WAF_ETC`, `HCW_WAF_DATA`, `HCW_WAF_IMAGE`.

Ghim phiên bản image bằng SHA commit thay vì `latest` khi chạy production:
`HCW_WAF_IMAGE=ghcr.io/hitechcloud-vietnam/hitechcloud-waf:<sha> docker compose up -d`.

### 7.2. Cluster bằng Docker

`cluster/deploy/` có `compose.controller.yaml`, `compose.node.yaml`,
`compose.dns.yaml` và `bootstrap-controller.sh` (sinh token, CA, chứng chỉ
controller). File cấu hình giống hệt mô hình systemd (mục 9), gắn vào
container qua `/etc/hcw` và `/var/lib/hcw` (chown UID 10001).

---

## 8. Mô hình C: Kubernetes

Xem đầy đủ trong [kubernetes.vi.md](kubernetes.vi.md). Tóm tắt:

```bash
git clone https://github.com/hitechcloud-vietnam/HiTechCloudWAF.git && cd HiTechCloudWAF
helm install waf deploy/helm/hitechcloud-waf --namespace hitechcloud-waf --create-namespace
kubectl -n hitechcloud-waf get pods,svc
# console
kubectl -n hitechcloud-waf port-forward svc/waf-hitechcloud-waf-console 9443:9443
# mật khẩu admin tự sinh (đổi và bật 2FA sau khi đăng nhập)
kubectl -n hitechcloud-waf get secret waf-hitechcloud-waf-auth -o jsonpath='{.data.admin-password}' | base64 -d; echo
# IP nhận traffic: trỏ DNS các site về đây
kubectl -n hitechcloud-waf get svc waf-hitechcloud-waf
```

Chart hỗ trợ: Service LoadBalancer/NodePort, PVC, Ingress cho console,
ServiceMonitor, PDB, HPA, DaemonSet + hostNetwork cho node biên, controller,
agent sidecar và DNS. Manifest thuần (không Helm) ở `deploy/kubernetes/`.
Lưu ý: chart hiện dùng token node dùng chung cho agent (chưa có tuỳ chọn
enrollment token).

---

## 9. Mô hình D: cluster nhiều node + DNS

Ví dụ dùng xuyên suốt:

| Máy | Vai trò | IP |
|---|---|---|
| `ctl` | controller + node **primary** (nơi quản trị site) | 203.0.113.5 |
| `hn-01` | node WAF, vùng `hn` | 203.0.113.10 |
| `hcm-01` | node WAF, vùng `hcm` | 198.51.100.20 |
| `ns1`, `ns2` | DNS authoritative | 203.0.113.53, 198.51.100.53 |

Zone WAF: `waf.example.vn`. Tên controller: `ctl.waf.example.vn`.

### 9.1. Máy controller (kiêm node primary)

```bash
sudo bash install.sh node                 # engine primary: nơi bạn tạo site/chứng chỉ
sudo bash install.sh controller --name ctl.waf.example.vn --ip 203.0.113.5
```

Controller installer:

- sinh token `admin`, `node` (dùng chung, cũ), `dns`, `primary-engine` trong
  `/etc/hcw/secrets/`;
- tạo CA riêng của cluster (`/etc/hcw/tls/ca.crt`, `ca.key`) và chứng chỉ
  controller cho `ctl.waf.example.vn` + IP;
- ghi `/etc/hcw/controller.yaml` (đồng bộ `site` và `cert` từ engine
  `127.0.0.1:9443`, `prune: true`);
- tạo service `hcw-controller` (cổng 7443).

Tạo bản ghi DNS `ctl.waf.example.vn A 203.0.113.5` (mục 9.5 có thể dùng chính
DNS của WAF).

Dashboard: `https://ctl.waf.example.vn:7443/` – đăng nhập bằng
`sudo cat /etc/hcw/secrets/admin.token`. Trình duyệt sẽ cảnh báo vì CA riêng;
có thể nhập `ca.crt` vào trình duyệt quản trị.

> **Bảo vệ `ca.key`**: chỉ dùng để ký chứng chỉ controller. Có thể chuyển nó ra
> khỏi máy (offline) sau khi cài.

Nếu node primary cũng nhận traffic khách thì cài thêm agent cho nó (mục 9.3)
để nó có mặt trong DNS.

### 9.2. Tạo token đăng ký cho từng node

Mỗi node nhận **secret riêng** qua một **enrollment token dùng một lần**:

- Dashboard → *Đăng ký node* → nhập `node_id` (ví dụ `hn-01`), pools `web`,
  region `hn`, thời hạn → *Tạo*. Token `hcwe_...` chỉ hiện **một lần**, kèm
  lệnh cài sẵn.
- Hoặc bằng API:

  ```bash
  ADMIN=$(sudo cat /etc/hcw/secrets/admin.token)
  curl -s --cacert /etc/hcw/tls/ca.crt -H "Authorization: Bearer $ADMIN" \
    -d '{"node_id":"hn-01","pools":["web"],"region":"hn","expires_in":86400,"comment":"node Ha Noi"}' \
    https://ctl.waf.example.vn:7443/v1/enroll-tokens
  # → {"id":"...","token":"hcwe_...","expires_at":"..."}
  ```

`expires_in` tính bằng giây (mặc định 24 giờ, tối đa 30 ngày). Token gắn
`pools`/`region` sẽ áp đặt các giá trị đó cho node.

### 9.3. Mỗi node WAF

Chép sang node: `ca.crt` của controller và token đăng ký (dùng `scp`, không dán
vào dòng lệnh):

```bash
# trên máy quản trị
scp ctl:/etc/hcw/tls/ca.crt hn-01:/root/ca.crt
ssh hn-01 'umask 077; cat > /root/enroll.token'   # dán token hcwe_..., Ctrl-D
```

Trên `hn-01`:

```bash
sudo bash install.sh node
sudo bash install.sh agent --controller https://ctl.waf.example.vn:7443 \
  --enroll-token-file /root/enroll.token --ca /root/ca.crt \
  --region hn --pools web --ipv4 203.0.113.10
sudo shred -u /root/enroll.token
```

- `--ipv4`: IP **public** mà khách truy cập (bắt buộc khi node nằm sau NAT;
  nếu bỏ, installer tự dò qua api.ipify.org).
- Agent đổi token lấy node secret và lưu ở `/var/lib/hcw/node-credential.json`
  (600); khởi động lại không cần token nữa.
- Agent kéo cấu hình (site, chứng chỉ) từ controller và áp vào engine cục bộ;
  **không tạo/sửa site trực tiếp trên node thường** – thay đổi sẽ bị ghi đè ở
  lần đồng bộ sau. Chỉ sửa trên node primary.

Kiểm tra:

```bash
journalctl -u hcw-agent -n 30 --no-pager     # "node enrolled", "configuration applied"
```

Trên dashboard, node hiện **Khỏe**, cột *Xác thực* = *secret riêng*.

**Dùng chung khoá challenge**: để khách đã qua anti-bot/mật khẩu ở node này
không phải làm lại khi DNS chuyển sang node khác, mọi node phải dùng cùng một
khoá:

```bash
# trên ctl (một lần)
sudo hcw token | sudo tee /etc/hcw-waf/challenge.key >/dev/null
# chép file này sang /etc/hcw-waf/challenge.key trên mọi node (chown hcwwaf, chmod 600), rồi trên MỌI node:
echo 'challenge_secret_file: /etc/hcw-waf/challenge.key' | sudo tee -a /etc/hcw-waf/waf.yaml
sudo systemctl restart hcw-waf
```

Lặp lại 9.2–9.3 cho `hcm-01`.

### 9.4. Tắt token dùng chung

Khi mọi node đều hiện *secret riêng*, trên controller:

```bash
sudo sed -i 's/^\(\s*\)node_token_file:.*/\1require_enrollment: true/' /etc/hcw/controller.yaml
sudo systemctl restart hcw-controller
```

(hoặc sửa tay: thêm `require_enrollment: true`, xoá `node_token_file`). Từ đây
token chung bị từ chối; node mới phải có enrollment token.

**Thu hồi một node** (máy bị mất, bị chiếm): xoá node trên dashboard hoặc
`DELETE /v1/nodes/<id>` → secret bị thu hồi ngay.
**Đổi secret định kỳ**: nút *Đổi secret* (hoặc `POST /v1/nodes/<id>/rotate`),
ghi token mới vào `/etc/hcw/secrets/enroll.token` trên node – agent tự đăng ký
lại, không cần khởi động lại.

### 9.5. Máy DNS (ít nhất 2)

Chép `ca.crt` và `dns.token` từ controller sang mỗi máy DNS, rồi:

```bash
sudo bash install.sh dns --controller https://ctl.waf.example.vn:7443 \
  --dns-token-file /root/dns.token --ca /root/ca.crt \
  --zone waf.example.vn --ns ns1.waf.example.vn,ns2.waf.example.vn
```

Sửa `/etc/hcw/dns.yaml` (giống nhau trên mọi máy DNS):

```yaml
dns:
  listen: ":53"
  controller_url: https://ctl.waf.example.vn:7443
  controller_ca: /etc/hcw/tls/ca.crt
  token_file: /etc/hcw/secrets/dns.token
  refresh: 5s
  # GeoDNS (tuỳ chọn): file .mmdb quốc gia, tự nạp lại khi file đổi
  # geoip_db: /etc/hcw/geoip/country.mmdb
  # pools:
  #   web:
  #     prefer_country:
  #       - {countries: [VN], region: hn}
  #       - {continents: [AS, OC], region: hcm}
  zones:
    - name: waf.example.vn
      ns: [ns1.waf.example.vn, ns2.waf.example.vn]
      hostmaster: noc.example.vn
      ttl: 30
      records:
        - {name: ns1, type: A, value: 203.0.113.53}
        - {name: ns2, type: A, value: 198.51.100.53}
        - {name: ctl, type: A, value: 203.0.113.5}
        # Tên khách hàng CNAME về: trả IP các node khỏe trong pool "web"
        - {name: edge, pool: web, max_answers: 2, fail_open: true}
        - {name: edge, type: AAAA, pool: web}
```

```bash
sudo systemctl restart hcw-dns
dig @127.0.0.1 waf.example.vn SOA +short
dig @127.0.0.1 edge.waf.example.vn A +short          # IP các node khỏe
dig @127.0.0.1 edge.waf.example.vn A +subnet=14.160.1.0/24 +short   # thử theo vùng
```

Bản ghi tĩnh khác (MX, TXT, CAA, SRV, CNAME, wildcard, ủy quyền subdomain) có
thể khai trong file trên hoặc quản lý trên dashboard (*Bản ghi DNS tĩnh*) /
API `/v1/dns/records`; file thắng khi trùng tên.

**Ủy quyền zone ở nhà đăng ký tên miền** (domain cha `example.vn`):

1. Tạo **glue record**: `ns1.waf.example.vn → 203.0.113.53`,
   `ns2.waf.example.vn → 198.51.100.53`.
2. Khai báo NS cho `waf.example.vn`: `ns1.waf.example.vn`, `ns2.waf.example.vn`.
3. Kiểm tra từ Internet: `dig +trace edge.waf.example.vn`.

### 9.6. Đưa website khách hàng vào cluster

1. Tạo site trên **console node primary** (`ctl`), như mục 5 – sau tối đa
   `sync_interval` (15 giây), site xuất hiện trên mọi node.
2. Khách hàng đặt `shop.example.vn CNAME edge.waf.example.vn.` (tên miền gốc
   apex không CNAME được: dùng A/ALIAS của nhà cung cấp DNS, hoặc chuyển NS).
3. Theo dõi trên dashboard controller: số request/chặn của từng node, sự kiện
   tấn công tập trung (`GET /v1/events`).

### 9.7. Bảo trì một node

```bash
ADMIN=$(sudo cat /etc/hcw/secrets/admin.token)
# rút node khỏi DNS (khách mới sẽ đi node khác sau TTL 30s)
curl -s --cacert /etc/hcw/tls/ca.crt -H "Authorization: Bearer $ADMIN" -X PATCH \
  -d '{"drain":true}' https://ctl.waf.example.vn:7443/v1/nodes/hn-01
# ... bảo trì, nâng cấp ...
curl -s --cacert /etc/hcw/tls/ca.crt -H "Authorization: Bearer $ADMIN" -X PATCH \
  -d '{"drain":false}' https://ctl.waf.example.vn:7443/v1/nodes/hn-01
```

Có thể chỉnh trọng số (`weight`) để node mạnh nhận nhiều traffic hơn – nút
trên dashboard hoặc `PATCH /v1/nodes/<id>`.

Node đổi IP thật: xoá node trên dashboard rồi đăng ký lại bằng token mới (node
đã đăng ký không được tự đổi IP qua heartbeat, để chống mạo danh).

---

## 10. WAF đứng sau load balancer / CDN

Nếu trước WAF còn load balancer (HAProxy, Nginx, ELB, Cloudflare…), khai báo
IP của chúng để engine lấy IP thật của khách từ `X-Forwarded-For`:

```yaml
trusted_proxies: [10.0.0.0/8]        # chỉ dải IP của load balancer, KHÔNG để 0.0.0.0/0
```

Engine đọc mọi dòng `X-Forwarded-For` từ phải sang trái, bỏ qua các hop tin
cậy. Không khai báo thì mọi khách sẽ mang IP của load balancer (rate limit,
chặn IP, GeoIP đều sai).

Với CDN, nên chặn ở tường lửa mọi kết nối tới cổng 80/443 không đến từ dải IP
của CDN.

---

## 11. Cấu hình nâng cao của node

File `/etc/hcw-waf/waf.yaml` – mẫu đầy đủ có chú thích: `waf/examples/waf.yaml`.
Mọi thay đổi trong file cần `sudo systemctl restart hcw-waf` (trừ GeoIP:
`sudo systemctl kill -s HUP hcw-waf`). Site, chứng chỉ, người dùng **không**
nằm trong file này mà ở API/console (lưu trong `/var/lib/hcw-waf`).

### 11.1. Chứng chỉ cho console/API

Mặc định engine tự sinh chứng chỉ tự ký (`/var/lib/hcw-waf/api.crt`). Dùng
chứng chỉ thật cho console:

```yaml
api:
  listen: 0.0.0.0:9443
  token_file: /etc/hcw-waf/api.token
  tls_cert: /etc/hcw-waf/console.crt
  tls_key: /etc/hcw-waf/console.key
  allow: [203.0.113.0/24]
```

(`chown hcwwaf` cho hai file, key quyền 600.)

### 11.2. Chặn theo quốc gia

`sudo bash install.sh node --geoip` tải DB-IP Lite vào
`/etc/hcw-waf/country.mmdb` và thêm `geoip_db`. Cập nhật hằng tháng: chạy lại
lệnh trên rồi `systemctl kill -s HUP hcw-waf`. Có thể dùng GeoLite2-Country của
MaxMind (cần tài khoản). Sau đó đặt `country_allow`/`country_deny` cho site.

### 11.3. Threat intelligence

```yaml
threat_intel:
  feeds:
    - {name: firehol_level1, url: https://iplists.firehol.org/files/firehol_level1.netset, refresh: 1h}
    - {name: spamhaus_drop, url: https://www.spamhaus.org/drop/drop.txt, refresh: 12h}
    - {name: local, url: file:///etc/hcw-waf/blocklist.txt, refresh: 5m}
```

Site bật `threat_intel: block` (hoặc `challenge`, `monitor`). Danh sách được
lưu bản sao trong `/var/lib/hcw-waf/threatintel` để dùng được khi khởi động
offline. Trạng thái xem ở trang *Hệ thống*.

### 11.4. Cảnh báo

```yaml
node_name: hn-01
alerts:
  kinds: [waf, rate_limit, bot, auth, geo, threat_intel]
  interval: 5m
  telegram:
    bot_token_file: /etc/hcw-waf/telegram.token   # token từ @BotFather
    chat_id: "-1001234567890"
  webhooks:
    - url: https://hooks.example.vn/waf
      secret: <chuỗi bí mật>                       # header X-HCW-Signature: sha256=HMAC(body)
```

Gửi thử: trang *Hệ thống* → *Gửi cảnh báo thử*, hoặc `hcwctl alerts test`.

### 11.5. Các tuỳ chọn khác

| Khoá | Mặc định | Ghi chú |
|---|---|---|
| `bind` | `""` (mọi địa chỉ) | Địa chỉ nghe cho cổng site |
| `body_limit_kb` | 1024 | Số KB body được WAF kiểm tra |
| `cache_mb` | 256 | Bộ nhớ cache response dùng chung (-1 = tắt) |
| `events_kept` | 5000 | Số sự kiện giữ trong RAM |
| `events_file` | – | File JSON lines lưu sự kiện |
| `access_log` | – | `{file, max_size_mb, max_files}` – một dòng JSON mỗi request |
| `extra_rules_file` | – | Rule SecLang riêng áp cho mọi site |
| `brand` | HiTechCloud WAF | Tên, màu, link hỗ trợ trên console và trang chặn |

---

## 12. Danh sách kiểm tra bảo mật

- [ ] Console/API (9443) **không** mở ra Internet: chỉ `127.0.0.1` + SSH tunnel,
      hoặc `api.allow` + tường lửa giới hạn IP quản trị.
- [ ] Đã tạo tài khoản riêng cho từng người, **bật 2FA**, không dùng API token
      hằng ngày; tài khoản chỉ xem dùng vai trò `viewer`.
- [ ] Server gốc chỉ nhận kết nối từ IP các node WAF.
- [ ] `trusted_proxies` chỉ chứa IP load balancer thật.
- [ ] Cluster: mọi node dùng **enrollment token**, đã bật
      `require_enrollment: true`; `ca.key` cất offline.
- [ ] Controller 7443 chỉ cho IP node, DNS và quản trị viên.
- [ ] Token và key đều quyền 600, sở hữu bởi user dịch vụ (installer đã làm).
- [ ] Bật `events_file`, `access_log` và chuyển log về hệ thống tập trung.
- [ ] Sao lưu định kỳ (mục 14) và đã thử khôi phục.
- [ ] Theo dõi trang Releases và nâng cấp kịp thời (bản vá bảo mật).
- [ ] Rule tuỳ chỉnh chỉ dùng `SecRule`/`SecAction`… (engine tự từ chối directive
      ghi file hay đọc file/mạng).

---

## 13. Giám sát, log và cảnh báo

### 13.1. Log dịch vụ

Mọi thành phần ghi log JSON ra journald:

```bash
journalctl -u hcw-waf -f
journalctl -u hcw-agent -u hcw-controller -u hcw-dns --since "1 hour ago"
journalctl -u hcw-waf -o cat | jq 'select(.level=="WARN" or .level=="ERROR")'
```

Thêm `-debug` vào `ExecStart` (qua `systemctl edit hcw-waf`) để xem chi tiết.

### 13.2. Log của engine

| File (`/var/lib/hcw-waf/`) | Nội dung |
|---|---|
| `access.log` (+ `.1`…`.N`) | Mỗi request một dòng: thời gian, site, IP, method, URI, status, `action` (`proxied`, `blocked`, `challenged`, `cached`, …), thời gian xử lý |
| `events.jsonl` | Sự kiện tấn công (rule khớp, dữ liệu khớp, quốc gia, feed…) |
| `audit.log` | Mọi thao tác quản trị và đăng nhập (đã che mật khẩu, key, token) |

Chuyển về hệ thống tập trung bằng Filebeat/Vector/Fluent Bit đọc các file trên.

### 13.3. Prometheus

Metrics tại `https://<node>:9443/api/open/metrics` (cần API token; IP của
Prometheus phải nằm trong `api.allow` nếu có):

```yaml
scrape_configs:
  - job_name: hitechcloud-waf
    scheme: https
    metrics_path: /api/open/metrics
    authorization:
      credentials_file: /etc/prometheus/hcw-waf.token
    tls_config:
      ca_file: /etc/prometheus/hcw-waf-api.crt     # /var/lib/hcw-waf/api.crt của node
    static_configs:
      - targets: ['203.0.113.10:9443', '198.51.100.20:9443']
```

Metrics chính: tổng request, số bị chặn/rate limit/ACL/bot theo site. Gợi ý
cảnh báo: tỉ lệ chặn tăng đột biến, `up == 0`, upstream không khỏe
(`hcwctl upstreams` / `GET /api/open/upstreams`).

Controller: `GET /healthz` (không cần token) cho kiểm tra sống;
`GET /v1/nodes` (admin) cho trạng thái node.

### 13.4. Cảnh báo tấn công

Telegram/webhook (mục 11.4). Trong cluster, dashboard controller gom sự kiện
của mọi node.

---

## 14. Sao lưu và khôi phục

### 14.1. Cấu hình engine (site + chứng chỉ)

```bash
hcwctl backup --file /root/backup/hcw-waf-$(date +%F).json     # chứa private key – giữ kín
# hoặc
curl -s --cacert /var/lib/hcw-waf/api.crt -H "X-HCW-API-TOKEN: $TOKEN" \
  https://127.0.0.1:9443/api/open/backup -o backup.json
```

Khôi phục (thay **toàn bộ** site và chứng chỉ; file được kiểm tra hợp lệ trước
khi áp dụng, lỗi thì không thay đổi gì):

```bash
hcwctl restore /root/backup/hcw-waf-2026-10-14.json     # hỏi xác nhận; thêm --yes khi chạy tự động
# hoặc API: body là phần "data" của file backup
jq .data backup.json | curl -s --cacert /var/lib/hcw-waf/api.crt -H "X-HCW-API-TOKEN: $TOKEN" \
  -H 'Content-Type: application/json' -d @- https://127.0.0.1:9443/api/open/restore
```

Cron hằng ngày (giữ 14 bản):

```bash
cat <<'EOF' | sudo tee /etc/cron.daily/hcw-waf-backup
#!/bin/sh
set -e
umask 077; mkdir -p /root/backup
cp /var/lib/hcw-waf/config.json /root/backup/config-$(date +%F).json
find /root/backup -name 'config-*.json' -mtime +14 -delete
EOF
sudo chmod +x /etc/cron.daily/hcw-waf-backup
```

### 14.2. File cần sao lưu theo vai trò

| Vai trò | Sao lưu | Ghi chú |
|---|---|---|
| node | `/etc/hcw-waf/` | `waf.yaml`, `api.token`, `challenge.key`, GeoIP, chứng chỉ console |
| node | `/var/lib/hcw-waf/config.json` | Site + chứng chỉ (giống file backup API) |
| node | `/var/lib/hcw-waf/users.json` | Tài khoản console, 2FA |
| node | `/var/lib/hcw-waf/challenge.key`, `api.crt`, `api.key` | Nếu dùng mặc định |
| controller | `/etc/hcw/` | Token, CA, chứng chỉ, `controller.yaml` |
| controller | `/var/lib/hcw/controller-state.json`, `node-credentials.json`, `dns-records.json` | Node, secret (hash), bản ghi DNS |
| agent | `/var/lib/hcw/node-credential.json` | Secret của node (mất thì đăng ký lại bằng token mới) |
| DNS | `/etc/hcw/dns.yaml` | Zone, bản ghi |

Khôi phục node từ file: dừng dịch vụ, chép lại `/etc/hcw-waf` và
`/var/lib/hcw-waf` (giữ chủ sở hữu `hcwwaf`, quyền 700/600), khởi động lại.

---

## 15. Nâng cấp và quay lại phiên bản cũ

### 15.1. Một node

```bash
curl -fsSLO https://github.com/hitechcloud-vietnam/HiTechCloudWAF/releases/latest/download/install.sh
sudo bash install.sh node --version v0.5.0
sudo systemctl restart hcw-waf
journalctl -u hcw-waf -n 20 --no-pager
```

Installer giữ nguyên `waf.yaml`, token và dữ liệu. Đọc `CHANGELOG.md` trước khi
nâng cấp (mục *thay đổi cần lưu ý*).

### 15.2. Cluster (cuốn chiếu, không gián đoạn)

1. **Sao lưu** controller (mục 14.2). Nâng cấp **controller** trước:
   `install.sh controller --name ... --version vX.Y.Z`.
   ⚠ Lệnh này **ghi lại `controller.yaml`** từ mẫu – sao lưu và chép lại các
   chỉnh sửa tay (ví dụ `require_enrollment`, `brand`) sau khi chạy.
2. Nâng cấp **từng máy DNS** (một máy một lúc): `install.sh dns ... --version`.
3. Với **từng node**: drain (mục 9.7) → đợi 1–2 phút →
   `install.sh node --version vX.Y.Z && install.sh agent ... --version vX.Y.Z`
   → kiểm tra log → bỏ drain → sang node tiếp theo.
4. Node primary nâng cấp cuối cùng.

### 15.3. Quay lại phiên bản cũ

Chạy lại installer với `--version` cũ. Định dạng dữ liệu tương thích ngược;
nếu bản mới đã thêm trường cấu hình mà bản cũ không biết, khôi phục bản sao
lưu tạo trước khi nâng cấp.

---

## 16. Hiệu năng và định cỡ

Kết quả đo chi tiết: [`bench/RESULTS.md`](../bench/RESULTS.md) (chạy lại bằng
`bench/cmd/hcwbench`). Một số số liệu tham khảo (CPU Xeon 2.1 GHz, mỗi lõi):

| Kịch bản | CPU / request | Tương đương mỗi lõi |
|---|---|---|
| Proxy thuần (`mode: off`) | ~0,12 ms | ~8 000 req/s |
| WAF paranoia 1, GET có query | ~3 ms | ~300 req/s |
| WAF paranoia 2, GET | ~5 ms | ~200 req/s |
| POST JSON 2 KB | ~40 ms | ~25 req/s |

Kinh nghiệm:

- Chi phí WAF tăng theo **số giá trị được kiểm tra** (tham số, cookie, khoá
  JSON). API nhận JSON lớn nên tách rule `skip_waf` cho đường dẫn tin cậy,
  hoặc giảm `body_limit_kb`.
- Bật **cache** cho file tĩnh và **gzip**: request trúng cache không tốn CPU WAF.
- Paranoia 1 cho đa số site; 2+ chỉ cho khu vực nhạy cảm (đăng nhập, quản trị).
- Mở rộng ngang: thêm node vào cluster, DNS tự chia tải.
- Hệ thống: `LimitNOFILE=131072` đã đặt sẵn; với lưu lượng lớn tăng
  `net.core.somaxconn` và dải cổng cục bộ (`net.ipv4.ip_local_port_range`).

---

## 17. Xử lý sự cố

| Triệu chứng | Nguyên nhân thường gặp | Cách xử lý |
|---|---|---|
| `hcw-waf` không khởi động, log `api.token ... at least 16 characters` | Token rỗng/ngắn | `hcw token \| sudo tee /etc/hcw-waf/api.token`, chown `hcwwaf` |
| `bind: permission denied` cổng 80/443 | Mất capability | Dùng unit của installer (`AmbientCapabilities=CAP_NET_BIND_SERVICE`) |
| `parse waf.yaml: field xxx not found` | Sai tên khoá (file kiểm tra chặt) | So với `waf/examples/waf.yaml` |
| Console không vào được | Chỉ nghe localhost / `api.allow` / tường lửa | SSH tunnel, hoặc thêm IP vào `allow` |
| Đăng nhập báo khoá 15 phút | Sai mật khẩu nhiều lần (10/IP, 50/tài khoản) | Đợi, hoặc đăng nhập bằng API token |
| Khách nhận **400** với URL có `../` hoặc `//` | Engine từ chối đường dẫn không chuẩn (chống vượt rule) | Sửa link phía ứng dụng; sự kiện loại `bad_path` |
| Mọi khách cùng một IP trong log | Thiếu `trusted_proxies` | Mục 10 |
| Request hợp lệ bị chặn 403 | Rule CRS chặn nhầm | Trang Sự kiện → *Báo chặn nhầm*, hoặc `disabled_rules`, `skip_waf` |
| **502** từ WAF | Upstream chết / sai địa chỉ / TLS upstream | `hcwctl upstreams`; bật `health_check`; `upstream_insecure` cho chứng chỉ tự ký |
| Let's Encrypt không cấp | Tên miền chưa trỏ về node, cổng 80 đóng, giới hạn tần suất | Thử `directory_url` staging; xem log `acme` |
| Agent: `401` | Token đăng ký đã dùng/hết hạn, secret bị thu hồi | Tạo token mới, ghi vào `/etc/hcw/secrets/enroll.token` |
| Agent: `403` | Secret của node khác / ID không khớp token | Kiểm tra `id` trong `agent.yaml` và `node_id` của token |
| Agent: `409` khi heartbeat | Node đổi IP | Xoá node trên dashboard, đăng ký lại |
| Agent: `x509: certificate signed by unknown authority` | Thiếu `controller_ca` | Chép `ca.crt` của controller, `--ca` |
| Node luôn *không khỏe* | Controller không probe được `probe_url` (cổng 80 bị chặn từ controller) | Mở 80 cho IP controller, hoặc sửa `probe_url` |
| DNS trả rỗng | Không node nào khỏe, node bị drain, sai tên pool | `GET /v1/pools`, dashboard; `fail_open: true` trả mọi node khi tất cả lỗi |
| DNS `REFUSED` | Tên không thuộc zone đã khai | Kiểm tra `zones[].name` |
| Site không đồng bộ sang node | Agent lỗi, sai token primary, sửa site trên node thường | Log `hcw-agent`, `GET /v1/sync` trên controller |

Thu thập thông tin khi cần hỗ trợ:

```bash
hcw-waf -version; hcw version
systemctl status hcw-waf hcw-agent hcw-controller hcw-dns --no-pager
journalctl -u hcw-waf -u hcw-agent --since "30 min ago" -o cat > hcw-logs.txt
```

(Không gửi kèm token, key hay file backup.)

---

## 18. Gỡ cài đặt

```bash
sudo systemctl disable --now hcw-waf hcw-agent hcw-controller hcw-dns 2>/dev/null
sudo rm -f /usr/local/bin/hcw-waf /usr/local/bin/hcw /usr/local/bin/hcwctl /etc/systemd/system/hcw-*.service
sudo systemctl daemon-reload
# Xoá cấu hình và dữ liệu (không thể khôi phục – sao lưu trước):
sudo rm -rf /etc/hcw-waf /etc/hcw /var/lib/hcw-waf /var/lib/hcw
sudo userdel hcwwaf 2>/dev/null; sudo userdel hcw 2>/dev/null
```

Trong cluster: xoá node trên dashboard trước (thu hồi secret, rút khỏi DNS).

---

## 19. Phụ lục: đường dẫn, file và dịch vụ

| Đường dẫn | Vai trò | Nội dung |
|---|---|---|
| `/usr/local/bin/hcw-waf` | node | Engine |
| `/usr/local/bin/hcw` | controller, agent, dns | `hcw controller\|agent\|dns\|token\|version` |
| `/etc/hcw-waf/waf.yaml` | node | Cấu hình engine |
| `/etc/hcw-waf/api.token` | node | API token (600) |
| `/var/lib/hcw-waf/` | node | `config.json`, `users.json`, `api.crt/key`, `challenge.key`, `events.jsonl`, `access.log`, `audit.log`, `threatintel/` |
| `/etc/hcw/controller.yaml` | controller | Cấu hình controller (bị ghi lại khi chạy lại installer) |
| `/etc/hcw/secrets/` | controller | `admin.token`, `node.token`, `dns.token`, `primary-engine.token` |
| `/etc/hcw/tls/` | controller | `ca.crt`, `ca.key`, `controller.crt`, `controller.key` |
| `/var/lib/hcw/` | controller | `controller-state.json`, `node-credentials.json`, `dns-records.json` |
| `/etc/hcw/agent.yaml` | agent | Cấu hình agent |
| `/etc/hcw/secrets/enroll.token`, `local-engine.token` | agent | Token đăng ký, token engine cục bộ |
| `/var/lib/hcw/node-credential.json` | agent | Secret riêng của node |
| `/etc/hcw/dns.yaml` | dns | Zone, bản ghi, GeoDNS |

| Dịch vụ systemd | User | Lệnh |
|---|---|---|
| `hcw-waf` | `hcwwaf` | `hcw-waf -config /etc/hcw-waf/waf.yaml` |
| `hcw-controller` | `hcw` | `hcw controller -config /etc/hcw/controller.yaml` |
| `hcw-agent` | `hcw` | `hcw agent -config /etc/hcw/agent.yaml` |
| `hcw-dns` | `hcw` | `hcw dns -config /etc/hcw/dns.yaml` |

Sinh token ngẫu nhiên: `hcw token` (64 ký tự hex).
