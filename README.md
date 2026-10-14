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
- Rate limit theo IP (chống brute force, HTTP flood).
- ACL IP allow/deny (CIDR).
- TLS nhiều chứng chỉ theo SNI, redirect HTTPS.
- Reverse proxy nhiều upstream có failover.
- Trang chặn whitelabel kèm Event ID.
- Log sự kiện tấn công và API quản trị.

Lộ trình (chưa có trong engine HiTechCloud): anti-bot challenge, auth
challenge, mã hóa HTML/JS động, console web quản trị.

**Cluster & DNS** (`cluster/`, viết mới):

- Một control plane quản lý nhiều node WAF ở nhiều region.
- Kiểm tra sức khỏe từng node bằng heartbeat, health của engine và probe HTTP.
- Drain node khi bảo trì; chỉnh weight cho từng node.
- Đồng bộ cấu hình (site, chứng chỉ…) từ node primary sang toàn bộ cluster, tự
  dịch ID tham chiếu chéo.
- DNS authoritative: chỉ trả IP node khỏe, weighted, ưu tiên region theo EDNS
  Client Subnet, failover tự động.
- Dashboard whitelabel (tên, màu, logo).

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
| `mcp_server/` | HiTechCloud WAF MCP Server |
| `management/` | Mã nguồn management/tcontrollerd (legacy) |
| `sdk/` | Plugin tích hợp gateway |

## Bắt đầu

1. Mỗi node: `waf/deploy/compose.yaml` (engine HiTechCloud + agent).
2. Control plane & DNS: [docs/cluster.vi.md](docs/cluster.vi.md), dùng
   `cluster/examples/controller-hcw-engine.yaml`.

## Giấy phép

GPL-3.0, xem [LICENSE.md](LICENSE.md). Đây là bản sửa đổi từ dự án
SafeLine (Chaitin Tech), xem [NOTICE.md](NOTICE.md). Các Docker image engine
có điều khoản riêng, xem [docs/LICENSING.vi.md](docs/LICENSING.vi.md).
