# HiTechCloud WAF Cluster — nhiều node + DNS

```
                    ┌──────────────── Control plane ────────────────┐
  Quản trị ───────► │ hcw controller :7443  (dashboard + API)        │
                    │   │  đọc cấu hình                              │
                    │   ▼                                            │
                    │ WAF engine "primary" (console :9443)           │
                    └───────────▲───────────────────▲────────────────┘
                     heartbeat  │  snapshot cấu hình │ endpoints (pool)
             ┌──────────────────┼──────────┐        │
             │                  │          │   ┌────┴─────────┐   ┌──────────────┐
     ┌───────┴──────┐   ┌───────┴──────┐   │   │ hcw dns #1   │   │ hcw dns #2   │
     │ Node HN-01   │   │ Node HCM-01  │ … │   │ (NS1)        │   │ (NS2)        │
     │ hcw agent    │   │ hcw agent    │   │   └──────▲───────┘   └──────▲───────┘
     │ WAF engine   │   │ WAF engine   │   │          │ truy vấn DNS     │
     └──────▲───────┘   └──────▲───────┘   │          └──── Người dùng ──┘
            └──── traffic HTTP/S ─────────────────────────────┘
```

## Thành phần (`cluster/`, binary `hcw`)

| Lệnh | Chạy ở đâu | Chức năng |
|---|---|---|
| `hcw controller` | Máy quản trị | Danh sách node, kiểm tra sức khỏe (heartbeat + probe HTTP), drain/weight, snapshot cấu hình từ engine primary, dashboard whitelabel |
| `hcw agent` | Mỗi node WAF | Gửi heartbeat (CPU, RAM, disk, health engine), áp dụng cấu hình (site, cert…) vào engine local qua API |
| `hcw dns` | ≥ 2 máy (NS1/NS2) | DNS authoritative: chỉ trả về IP các node khỏe trong pool; weighted, ưu tiên region theo EDNS Client Subnet, fail-open tùy chọn |
| `hcw token` | – | Sinh token ngẫu nhiên |

### Sức khỏe node

Một node được coi là healthy khi đủ cả 3 điều kiện:

1. Heartbeat gần nhất cách đây không quá `heartbeat_timeout`.
2. Engine local trả lời health API.
3. `probe_url` (nếu có) trả về mã < 500. Controller tự gọi probe, và URL bắt
   buộc trỏ về đúng IP của node để tránh SSRF.

Node đang **drain** bị loại khỏi DNS nhưng vẫn ở trong cluster (dùng khi bảo
trì).

### Đồng bộ cấu hình

Controller đọc các resource khai báo trong `controller.primary.resources` từ
engine primary và tạo snapshot có `revision`. Khi agent thấy revision mới, nó
so khớp theo `key_fields`:

- tạo object còn thiếu, cập nhật object khác;
- xóa object thừa nếu `prune: true`;
- tự dịch ID tham chiếu chéo giữa các node (ví dụ `site.cert_id` → `cert`).

Token API của từng engine chỉ nằm trên node đó, không đi qua controller.

> Đường dẫn và tên trường API mặc định trong `examples/controller.yaml` phải
> được đối chiếu với tài liệu API của phiên bản engine đang chạy. Bật `prune`
> sau khi đã kiểm tra.

### Thống kê và sự kiện tập trung

Với engine HiTechCloud, mỗi heartbeat của agent gửi kèm:

- bộ đếm request/chặn của node;
- các sự kiện tấn công mới kể từ lần trước (tối đa 100 mỗi lần).

Controller cộng dồn thành số liệu toàn cluster và giữ 5000 sự kiện gần nhất
trong bộ nhớ. Xem qua dashboard hoặc `GET /v1/events?limit=&node=` (admin).

![Dashboard cluster](images/cluster-dashboard.png)

## Triển khai nhanh

```bash
# 1) Control plane
sudo cluster/deploy/bootstrap-controller.sh controller.example.vn 203.0.113.5
sudo cp cluster/examples/controller.yaml /etc/hcw/controller.yaml   # sửa cho phù hợp
# Tạo API token trên console primary → /etc/hcw/secrets/primary-engine.token
docker compose -f cluster/deploy/compose.controller.yaml up -d --build

# 2) Mỗi node WAF (đã chạy engine stack bằng compose.yaml ở gốc repo)
#    copy ca.crt + node.token từ controller sang /etc/hcw/...
sudo cp cluster/examples/agent.yaml /etc/hcw/agent.yaml             # sửa id/ip/region/pools
docker compose -f cluster/deploy/compose.node.yaml up -d --build

# 3) DNS (≥ 2 máy) – copy ca.crt + dns.token
sudo cp cluster/examples/dns.yaml /etc/hcw/dns.yaml
docker compose -f cluster/deploy/compose.dns.yaml up -d --build
```

Ở nhà đăng ký tên miền, khai báo `ns1`/`ns2` (glue record) cho zone, ví dụ
`waf.hitechcloud.vn`. Khách hàng trỏ CNAME tên miền của mình về
`edge.waf.hitechcloud.vn` (hoặc một record riêng cho từng khách).

Dashboard: `https://controller.example.vn:7443/`, đăng nhập bằng `admin.token`.

## API controller

| Method & path | Token | Mô tả |
|---|---|---|
| `GET /healthz` | – | liveness |
| `POST /v1/heartbeat` | node | agent báo cáo |
| `GET /v1/config/snapshot` | node | snapshot cấu hình |
| `GET /v1/nodes`, `GET/PATCH/DELETE /v1/nodes/{id}` | admin | quản lý node (`{"drain":true}`, `{"weight_override":50}`) |
| `GET /v1/pools` | admin | các pool + endpoint |
| `GET /v1/events` | admin | sự kiện tấn công toàn cluster |
| `GET /v1/pools/{pool}/endpoints` | dns/admin | dùng cho DNS |
| `GET/POST /v1/sync` | admin | trạng thái / đồng bộ ngay |

## Kiểm thử

```bash
cd cluster && go vet ./... && go test -race ./...
```
