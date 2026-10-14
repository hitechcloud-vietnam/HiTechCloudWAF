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

**Bảo vệ ứng dụng web** (WAF engine):

- Chặn tấn công web: SQL injection, XSS, code/OS command injection, CRLF, XXE,
  SSRF, path traversal, backdoor…
- Giới hạn tốc độ truy cập (chống brute force, HTTP flood).
- Anti-bot challenge, xác thực truy cập (auth challenge).
- Bảo vệ động: mã hóa HTML/JS.
- ACL theo IP.

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
| `compose.yaml`, `scripts/manage.py` | Stack WAF engine cho một node |
| `cluster/` | Controller, agent và DNS cho cluster (Go) — xem [docs/cluster.vi.md](docs/cluster.vi.md) |
| `branding/console/` | Overlay whitelabel cho image console |
| `mcp_server/` | HiTechCloud WAF MCP Server |
| `management/` | Mã nguồn management/tcontrollerd (legacy) |
| `sdk/` | Plugin tích hợp gateway |

## Bắt đầu

1. Cài stack WAF engine trên từng node (`compose.yaml`).
2. Dựng cluster theo [docs/cluster.vi.md](docs/cluster.vi.md).

## Giấy phép

GPL-3.0, xem [LICENSE.md](LICENSE.md). Đây là bản sửa đổi từ dự án
SafeLine (Chaitin Tech), xem [NOTICE.md](NOTICE.md). Các Docker image engine
có điều khoản riêng, xem [docs/LICENSING.vi.md](docs/LICENSING.vi.md).
