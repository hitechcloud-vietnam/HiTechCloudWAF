English: [README.en.md](README.en.md)

<p align="center">
  <img src="/images/logo.svg" width="360" alt="HiTechCloud WAF" />
</p>

<h4 align="center">HiTechCloud WAF — bảo vệ ứng dụng web của bạn</h4>

HiTechCloud WAF is a self-hosted **WAF (Web Application Firewall) / reverse
proxy** that protects your web apps from attacks and exploits, with built-in
**multi-node clustering** and **health-checked DNS** in one platform.

HiTechCloud WAF là tường lửa ứng dụng web tự triển khai, chạy như một reverse
proxy. Nền tảng có sẵn **cluster nhiều node** và **DNS có kiểm tra sức khỏe**.
Phát triển bởi Pho Tue SoftWare Solutions JSC / HiTechCloud-VN.

## Tính năng

**HiTechCloud WAF Engine** (`waf/`, mã nguồn mở, độc lập): reverse proxy +
OWASP Coraza + Core Rule Set v4, xem [docs/engine.vi.md](docs/engine.vi.md).

Đã có trong engine HiTechCloud:

- Chặn tấn công web theo OWASP CRS: SQL injection, XSS, RCE/command injection,
  LFI/RFI, path traversal, protocol attack, scanner… (đã kiểm thử ở cả query
  lẫn body JSON/form).
- Chế độ block / monitor / off, paranoia 1–4, tắt rule chặn nhầm theo từng site.
- Rate limit theo IP (chống brute force, HTTP flood) và rule theo đường dẫn
  (giới hạn riêng `/login`, whitelist đối tác, bỏ qua WAF, chặn đường dẫn).
- Cảnh báo tấn công qua Telegram và webhook (có chữ ký HMAC).
- ACL IP allow/deny (CIDR), chặn/cho phép theo quốc gia (GeoIP).
- TLS nhiều chứng chỉ theo SNI, redirect HTTPS.
- Reverse proxy nhiều upstream: round-robin, trọng số, least_conn, ip_hash,
  sticky session, health check chủ động, sửa header request/response.
- Cache response trong RAM và nén gzip.
- Threat intelligence: tự tải danh sách IP xấu (FireHOL, Spamhaus…); bot tìm
  kiếm thật (Googlebot, Bingbot) được xác minh bằng reverse DNS.
- Anti-bot challenge (JS proof-of-work) và auth challenge (mật khẩu, chống brute force).
- Bảo vệ HTML/JS động: nội dung được mã hoá khác nhau mỗi lần tải, chống thu
  thập dữ liệu (scraping).
- HTTPS tự động Let's Encrypt, HTTP/2, HSTS; rule SecLang tuỳ chỉnh; metrics
  Prometheus.
- Trang chặn whitelabel kèm Event ID.
- Console web quản trị whitelabel: dashboard, ứng dụng, sự kiện (chặn IP hoặc
  báo chặn nhầm chỉ với 1 click), chứng chỉ; nhiều tài khoản với vai trò
  admin/viewer và xác thực 2 lớp (TOTP); giao diện tiếng Việt và tiếng Anh.
- Access log JSON, audit log, sao lưu/khôi phục cấu hình; CLI `hcwctl`.
- Log sự kiện tấn công và API quản trị (đặc tả OpenAPI: [docs/api/](docs/api/README.md)).

![Console](docs/images/console-dashboard.png)

**Cluster & DNS** (`cluster/`, viết mới):

- Một control plane quản lý nhiều node WAF ở nhiều region.
- Kiểm tra sức khỏe từng node bằng heartbeat, health của engine và probe HTTP.
- Drain node khi bảo trì; chỉnh weight cho từng node.
- Đồng bộ cấu hình (site, chứng chỉ…) từ node primary sang toàn bộ cluster, tự
  dịch ID tham chiếu chéo.
- DNS authoritative: chỉ trả IP node khỏe, weighted, ưu tiên region theo EDNS
  Client Subnet hoặc theo quốc gia (GeoDNS), failover tự động; bản ghi tĩnh
  A/AAAA/CNAME/TXT/MX/NS/SRV/CAA quản lý qua API và dashboard.
- Dashboard whitelabel (tên, màu, logo), thống kê và sự kiện tấn công tập trung
  từ mọi node.

**Tích hợp:**

- MCP server cho AI (`mcp_server/`).
- Plugin cho Ingress-NGINX, Kong và lua-resty-t1k (`sdk/`).

## Cấu trúc repo

| Thư mục | Nội dung |
|---|---|
| `waf/` | **HiTechCloud WAF Engine** (Go, Coraza + CRS) — xem [docs/engine.vi.md](docs/engine.vi.md) |
| `compose.yaml`, `scripts/manage.py` | Stack engine upstream (image Chaitin, cần thỏa thuận OEM) |
| `cluster/` | Controller, agent và DNS cho cluster (Go) — xem [docs/cluster.vi.md](docs/cluster.vi.md) |
| `branding/console/` | Overlay whitelabel cho image console |
| `ctl/` | `hcwctl` – CLI quản trị, xem [ctl/README.md](ctl/README.md) |
| `deploy/` | Helm chart và manifest Kubernetes, xem [docs/kubernetes.vi.md](docs/kubernetes.vi.md) |
| `bench/` | Benchmark hiệu năng, xem [bench/RESULTS.md](bench/RESULTS.md) |
| `mcp_server/` | HiTechCloud WAF MCP Server |
| `management/` | Mã nguồn management/tcontrollerd (legacy) |
| `sdk/` | Plugin tích hợp gateway |
| `docs/api/` | Đặc tả OpenAPI 3.1 của API engine và controller — xem [docs/api/README.md](docs/api/README.md) |
| `docs/en/` | Tài liệu tiếng Anh |

## Bắt đầu

```bash
curl -fsSLO https://github.com/hitechcloud-vietnam/HiTechCloudWAF/releases/latest/download/install.sh
sudo bash install.sh node            # một node WAF + console
```

Cluster nhiều node, DNS và Docker: [docs/install.vi.md](docs/install.vi.md),
kiến trúc ở [docs/cluster.vi.md](docs/cluster.vi.md).

Kubernetes (Helm chart hoặc manifest thuần): [docs/kubernetes.vi.md](docs/kubernetes.vi.md).

## Giấy phép

GPL-3.0, xem [LICENSE.md](LICENSE.md). Đây là bản sửa đổi từ dự án
SafeLine (Chaitin Tech), xem [NOTICE.md](NOTICE.md). Các Docker image engine
có điều khoản riêng, xem [docs/LICENSING.vi.md](docs/LICENSING.vi.md).
