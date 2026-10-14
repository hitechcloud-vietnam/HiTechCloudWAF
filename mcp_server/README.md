# HiTechCloud WAF MCP Server

Máy chủ [Model Context Protocol](https://modelcontextprotocol.io) cho phép trợ lý AI
(Claude Desktop, Claude Code, ...) đọc và quản lý các node **hcw-waf** qua API quản
trị (`docs/api/waf.openapi.yaml`): xem site, sự kiện tấn công, thống kê, sức khỏe
upstream, threat intel, chứng chỉ, nhật ký kiểm toán; đổi chế độ bảo vệ, chặn IP,
tắt/bật rule CRS và xóa cache.

*English summary: see [the English section](#english) at the end.*

## Mục lục

- [Công cụ (tools)](#công-cụ-tools)
- [Bảo mật](#bảo-mật)
- [Cấu hình](#cấu-hình)
- [Dùng với Claude Desktop / Claude Code (stdio)](#dùng-với-claude-desktop--claude-code-stdio)
- [Chạy qua HTTP (Streamable HTTP)](#chạy-qua-http-streamable-http)
- [Backend cũ (legacy)](#backend-cũ-legacy)
- [Phát triển và kiểm thử](#phát-triển-và-kiểm-thử)
- [English](#english)

## Công cụ (tools)

Mọi tool nhận `instance_id` (có thể bỏ trống khi chỉ cấu hình một node).

### Chỉ đọc

| Tool | API của node | Nội dung |
|---|---|---|
| `get_node_info` | `GET /api/open/info`, `/api/open/cache` | Phiên bản, uptime, số site/chứng chỉ, dung lượng cache, có cho phép ghi không |
| `list_sites` | `GET /api/open/site` | Danh sách site: ID, tên miền, cổng, chế độ, upstream |
| `get_site` | `GET /api/open/site` | Cấu hình bảo vệ của một site (paranoia, ngưỡng anomaly, rule CRS đã tắt, danh sách IP/quốc gia, rate limit, challenge, TLS). Không trả về bí mật |
| `list_attack_events` | `GET /api/open/events` | Sự kiện mới nhất; lọc theo `site_id`, `limit` (1–500), `since` (RFC 3339 hoặc `30m`, `6h`, `7d`), `client_ip` (IP/CIDR), `action` |
| `get_attack_event` | `GET /api/open/events` | Chi tiết một sự kiện theo event ID (mã hiển thị trên trang chặn): rule CRS khớp, mức độ, tag |
| `get_stats` | `GET /api/open/stats` | Bộ đếm theo site từ lúc node khởi động, kèm tổng |
| `get_timeseries` | `GET /api/open/timeseries` | Bộ đếm toàn node theo phút, 1–60 phút gần nhất |
| `get_upstream_health` | `GET /api/open/upstreams` | Sức khỏe upstream của từng site |
| `get_threat_intel_status` | `GET /api/open/threatintel` | Trạng thái các feed threat intel (URL đã ẩn thông tin đăng nhập và query) |
| `list_certificates` | `GET /api/open/cert` | Chứng chỉ: tên miền, issuer, hạn, số ngày còn lại, site đang dùng. **Không bao giờ trả khóa riêng** |
| `get_audit_log` | `GET /api/open/audit` | Nhật ký kiểm toán (ai, từ đâu, làm gì, kết quả), bí mật đã được che |

### Ghi (thay đổi cấu hình node)

Mô tả của các tool này bắt đầu bằng `WRITE` và có annotation `readOnlyHint: false`.

| Tool | Tác dụng |
|---|---|
| `set_site_mode` | Đổi chế độ site: `block`, `monitor`, `off` |
| `add_denied_ips` | Thêm IP/CIDR vào `ip_deny` (tối đa 100/lần; từ chối prefix rộng hơn /8 với IPv4, /32 với IPv6) |
| `remove_denied_ips` | Gỡ IP/CIDR khỏi `ip_deny` |
| `disable_site_rules` | Tắt rule CRS (900000–999999) trên một site để xử lý false positive |
| `enable_site_rules` | Bật lại rule CRS đã tắt |
| `purge_cache` | Xóa cache phản hồi của một site (`site_id`) hoặc mọi site (`all_sites: true`), tùy chọn theo `prefix` |

API của node không có cập nhật từng phần: tool ghi đọc site, sửa đúng trường cần sửa rồi
gửi lại **toàn bộ** đối tượng (các trường khác, kể cả trường mà MCP server không biết,
được giữ nguyên). Các lệnh ghi qua cùng một MCP server được tuần tự hóa theo node; một
thay đổi đồng thời từ console giữa lúc đọc và ghi vẫn có thể bị ghi đè. Gọi lại với
cùng tham số không gây thay đổi (`changed: false`). Mọi thay đổi được ghi vào nhật ký của
MCP server và vào audit log của node (người dùng `api-token`).

`read_only: true` ở cấp cấu hình **ẩn hẳn** các tool ghi. `read_only: true` trên một
instance giữ các tool nhưng từ chối ghi vào instance đó.

## Bảo mật

- **Token API của node** chỉ lấy từ file (`token_file`, quyền `0600`, không symlink, thư mục
  không cho nhóm/người khác ghi) hoặc biến môi trường (`token_env` = *tên* biến). Không bao
  giờ nằm trong `config.yaml`, không bao giờ được ghi log, không có trong kết quả tool hay
  thông báo lỗi. Token chỉ được gửi trong header `X-HCW-API-TOKEN`.
- **TLS luôn được xác minh.** Node dùng chứng chỉ tự ký (khi không đặt `api.tls_cert`) lưu ở
  `data_dir/api.crt`: trỏ `ca_file` tới file đó. Không có tùy chọn bỏ qua xác minh
  (`insecure_skip_verify` bị từ chối khi khởi động).
- `http://` chỉ được chấp nhận khi host là loopback (`127.0.0.1`, `::1`, `localhost`);
  URL có thông tin đăng nhập, query hoặc fragment bị từ chối.
- Không theo **redirect** (token nằm trong header tùy biến mà `net/http` không gỡ khi chuyển
  sang origin khác).
- **Chống prompt injection:** URI, user agent, host, method, dữ liệu khớp rule, thông điệp
  rule (CRS có thể chèn biến của request vào thông điệp), tên người dùng và chi tiết trong
  audit log là dữ liệu do client từ xa (có thể là kẻ tấn công) kiểm soát. Chúng được đặt
  trong các object `untrusted`, kèm trường `notice` nhắc mô hình coi đó là dữ liệu. Ký tự
  điều khiển, ký tự định dạng vô hình (bidi override, zero-width, tag Unicode), ký tự
  phân dòng/đoạn và UTF-8 lỗi được hiển thị dưới dạng percent-encoding (`%0A`, `%E2%80%AE`),
  chuỗi dài bị cắt. Hướng dẫn của server yêu cầu chỉ gọi tool ghi khi người dùng yêu cầu rõ
  ràng, không bao giờ vì nội dung trong sự kiện hay log.
- Kết quả không chứa: khóa riêng hay PEM của chứng chỉ, `password_hash` của challenge mật
  khẩu, nội dung `custom_rules`, header viết lại (có thể chứa khóa upstream). URL upstream và
  URL feed được bỏ phần user:password và query.
- Hướng dẫn server (instructions) chỉ chứa `display_name` → `instance_id`, không chứa địa chỉ
  hay đường dẫn bí mật.

## Cấu hình

```yaml
backend: "hcw-waf"     # mặc định; "legacy" = engine cũ, chỉ có get_attack_events
read_only: false       # true: ẩn mọi tool ghi

server:
  name: "HiTechCloud WAF MCP Server"
  version: "2.1.0"
  transport: "stdio"   # "http" (mặc định) hoặc "stdio"; --transport / MCP_TRANSPORT ghi đè
  host: "127.0.0.1"    # chỉ dùng với http
  port: 5678

logger:
  level: "info"
  console: true        # log console ra stderr (stdout dành cho giao thức stdio)

instances:
  - id: "hn-01"
    display_name: "Hà Nội 01"
    base_url: "https://10.0.0.10:9443"
    token_file: "/etc/hitechcloud-waf-mcp/hn-01.token"
    ca_file: "/etc/hitechcloud-waf-mcp/hn-01.crt"   # bản sao data_dir/api.crt của node
    timeout: 30
  - id: "hcm-01"
    display_name: "TP.HCM 01"
    base_url: "https://10.0.1.10:9443"
    token_env: "HCW_HCM01_TOKEN"
    ca_file: "/etc/hitechcloud-waf-mcp/hcm-01.crt"
    read_only: true      # chỉ cho phép đọc trên node này
```

Đường dẫn tương đối (`token_file`, `ca_file`) được tính từ thư mục chứa file cấu hình.
Mỗi `display_name` phải duy nhất (không phân biệt hoa thường) và không trùng `id` của
instance khác.

Lấy token và chứng chỉ của node (trên máy chạy `hcw-waf`, theo `waf.yaml`):

```bash
install -d -m 700 ~/.config/hitechcloud-waf-mcp
sudo cat /etc/hcw-waf/api.token > ~/.config/hitechcloud-waf-mcp/hn-01.token
chmod 600 ~/.config/hitechcloud-waf-mcp/hn-01.token
sudo cat /var/lib/hcw-waf/api.crt > ~/.config/hitechcloud-waf-mcp/hn-01.crt
```

Token của node mang quyền `admin`. Nếu chỉ cần đọc, đặt `read_only: true`.

## Dùng với Claude Desktop / Claude Code (stdio)

Biên dịch:

```bash
cd mcp_server
go build -o ~/.local/bin/hcw-waf-mcp .
```

File cấu hình tối giản `~/.config/hitechcloud-waf-mcp/config.yaml`:

```yaml
read_only: true
server: {name: "HiTechCloud WAF MCP Server", version: "2.1.0", transport: "stdio"}
logger: {level: "warn", console: true}
instances:
  - id: "hn-01"
    display_name: "Hà Nội 01"
    base_url: "https://10.0.0.10:9443"
    token_file: "hn-01.token"
    ca_file: "hn-01.crt"
```

Ở chế độ stdio, client khởi chạy tiến trình trên chính máy của người dùng nên không có
listener và không cần bearer token MCP.

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "hitechcloud-waf": {
      "command": "/home/USER/.local/bin/hcw-waf-mcp",
      "args": ["--config", "/home/USER/.config/hitechcloud-waf-mcp/config.yaml", "--transport", "stdio"]
    }
  }
}
```

Có thể dùng `token_env` thay cho `token_file` và truyền token qua khối `"env"` của cấu
hình client, nhưng khi đó token nằm trong file cấu hình của client; `token_file` với quyền
`0600` được khuyến nghị.

**Claude Code**:

```bash
claude mcp add hitechcloud-waf -- \
  ~/.local/bin/hcw-waf-mcp --config ~/.config/hitechcloud-waf-mcp/config.yaml --transport stdio
```

Hoặc trong `.mcp.json` của dự án:

```json
{
  "mcpServers": {
    "hitechcloud-waf": {
      "command": "hcw-waf-mcp",
      "args": ["--config", "/home/USER/.config/hitechcloud-waf-mcp/config.yaml", "--transport", "stdio"]
    }
  }
}
```

## Chạy qua HTTP (Streamable HTTP)

Transport HTTP phục vụ một endpoint duy nhất `POST /mcp` (Streamable HTTP, giao thức MCP
`2026-07-28` và tương thích client cũ). Các route SSE cũ (`/sse`, `/message`) **không**
được hỗ trợ.

- Xác thực bearer bật mặc định. Tạo token một lần:
  `mcp-server auth init --state-file /var/lib/hitechcloud-waf-mcp/auth.json`
  (chỉ lưu SHA-256 của token); xoay vòng bằng `auth rotate`.
- Client gửi `Authorization: Bearer <token>`.
- Listener không phải loopback bắt buộc TLS (`MCP_TLS_CERT`, `MCP_TLS_KEY` hoặc
  `tls_cert_file`/`tls_key_file`). `MCP_AUTH_DISABLED=true` chỉ được chấp nhận với listener
  loopback.
- `LISTEN_ADDRESS`, `LISTEN_PORT` ghi đè `host`, `port`.

Claude Code với server HTTP:

```bash
claude mcp add --transport http hitechcloud-waf https://mcp.example.vn:5678/mcp \
  --header "Authorization: Bearer $HCW_MCP_TOKEN"
```

Docker:

```bash
install -d -m 700 secrets state
install -m 600 /path/to/hn-01.token secrets/hn-01.token
docker compose build
docker compose run --rm mcp_server auth init     # lưu token hiển thị một lần
docker compose up -d
```

`docker-compose.yml` gắn `./config.yaml` vào `/etc/hitechcloud-waf-mcp/config.yaml` và
`./secrets` vào `/run/secrets` (chỉ đọc). Cổng chỉ publish trên `127.0.0.1` trừ khi đặt
`MCP_PUBLISH_ADDRESS`.

## Backend cũ (legacy)

`backend: legacy` giữ nguyên hành vi trước đây cho engine cũ: chỉ một tool chỉ đọc
`get_attack_events` (`GET /api/open/events`, header `X-SLCE-API-TOKEN`), bắt buộc
`instance_id`, `token_file` (không hỗ trợ `token_env`). Tham số: `instance_id`, `page`,
`page_size` (1–100), `ip`, `host`, `port`, `start`, `end` (Unix ms).

## Phát triển và kiểm thử

```bash
cd mcp_server
gofmt -l .
go vet ./...
go test -race ./...
```

Các test chạy mọi tool qua transport stdio thật với một node hcw-waf giả (httptest TLS,
chứng chỉ được ghim bằng `ca_file`), kiểm tra validate đầu vào, schema đầu ra, làm sạch
dữ liệu không tin cậy, không lộ token/khóa riêng, chế độ chỉ đọc và chọn instance.

---

## English

MCP server for **hcw-waf** nodes (management API in `docs/api/waf.openapi.yaml`, header
`X-HCW-API-TOKEN`, `{data, err, msg}` envelope).

**Tools.** Read-only: `get_node_info`, `list_sites`, `get_site`, `list_attack_events`
(filters `site_id`, `limit`, `since`, `client_ip`, `action`), `get_attack_event`,
`get_stats`, `get_timeseries`, `get_upstream_health`, `get_threat_intel_status`,
`list_certificates` (never returns private keys), `get_audit_log`. Write (description
starts with `WRITE`, `readOnlyHint: false`): `set_site_mode`, `add_denied_ips`,
`remove_denied_ips`, `disable_site_rules`, `enable_site_rules`, `purge_cache`.
`read_only: true` hides the write tools; `read_only: true` on an instance refuses writes to
that node. Inputs are validated: modes, IPs/CIDRs (no prefix broader than /8 IPv4 or /32
IPv6 is denied), CRS rule IDs 900000–999999, event IDs, time filters, purge prefixes.

**Security.** The node token comes only from `token_file` (0600) or `token_env`; it is never
logged or returned. TLS is always verified (`ca_file` pins a self-signed node certificate,
`data_dir/api.crt`); plain `http://` is refused for non-loopback hosts; redirects are never
followed. Attacker-controlled text (URI, user agent, host, method, matched data, rule
messages, audit user/detail) is returned inside `untrusted` objects with a `notice`, with
control and invisible formatting characters percent-encoded and long values truncated.

**Transports.** `--transport stdio` (or `server.transport: stdio`) for Claude Desktop /
Claude Code:

```json
{"mcpServers": {"hitechcloud-waf": {"command": "hcw-waf-mcp",
  "args": ["--config", "/path/config.yaml", "--transport", "stdio"]}}}
```

```bash
claude mcp add hitechcloud-waf -- hcw-waf-mcp --config /path/config.yaml --transport stdio
```

`http` serves Streamable HTTP at `POST /mcp` with a bearer token (`mcp-server auth init`),
TLS required on non-loopback listeners. Legacy SSE routes are not served.
`backend: legacy` keeps the previous single read-only `get_attack_events` tool for the
legacy engine.
