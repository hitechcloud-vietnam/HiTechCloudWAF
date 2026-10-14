# HiTechCloud WAF Engine (`waf/`)

Engine WAF riêng của HiTechCloud, mã nguồn mở hoàn toàn, **không phụ thuộc
image của Chaitin**. Binary: `hcw-waf`.

## Luồng xử lý một request

```
Client ─► listener (HTTP / HTTPS theo SNI)
          │
          ├─ chọn site theo Host (tên chính xác, wildcard *.domain, hoặc "_")
          ├─ redirect HTTPS (tuỳ chọn)
          ├─ ACL IP: ip_deny → 403, ip_allow (nếu có) → 403
          ├─ Rate limit theo IP/site → 429 + thời gian chặn
          ├─ Auth challenge (mật khẩu) → trang đăng nhập
          ├─ Anti-bot challenge (JS proof-of-work) → trang kiểm tra trình duyệt
          ├─ OWASP Coraza + Core Rule Set v4 (SQLi, XSS, RCE, LFI/RFI,
          │   path traversal, scanner, protocol attack…) → 403
          ├─ Reverse proxy → upstream (round-robin; upstream lỗi bị loại 10s)
          └─ Bảo vệ động: mã hoá HTML/JS trong response (tuỳ chọn)
```

Trang chặn mang thương hiệu HiTechCloud và hiển thị **Event ID** để tra cứu.
Mỗi lần chặn sinh một sự kiện, lưu trong bộ nhớ và ghi vào file JSONL.

## Chế độ bảo vệ của từng site

| Trường | Ý nghĩa |
|---|---|
| `mode` | `block` (chặn), `monitor` (chỉ ghi log), `off` (proxy thuần) |
| `paranoia` | 1–4. Mặc định 1, ít chặn nhầm. PL3–4 bắt được nhiều hơn nhưng cần tinh chỉnh |
| `anomaly_threshold` | Ngưỡng điểm CRS để chặn (mặc định 5) |
| `disabled_rules` | Danh sách ID rule CRS tắt cho site, dùng khi bị chặn nhầm |
| `rate_limit` | `{requests, window_sec, block_sec}` |
| `ip_allow` / `ip_deny` | Danh sách IP hoặc CIDR |
| `ports` | `"80"`, `"443_ssl"` (cổng `_ssl` bắt buộc có `cert_id`) |
| `upstreams` | `http(s)://host:port`, có thể nhiều upstream |
| `upstream_host`, `upstream_insecure`, `redirect_https` | Tuỳ chọn proxy |
| `auto_tls` | Tự cấp và gia hạn chứng chỉ Let's Encrypt (cần `acme.enabled`) |
| `hsts` | Thêm `Strict-Transport-Security` vào các response HTTPS |
| `country_allow` / `country_deny` | Mã quốc gia ISO, ví dụ `VN`. Cần `geoip_db` trên node |
| `dynamic_protection` | Mã hoá HTML/JS mỗi response, chống thu thập dữ liệu (xem bên dưới) |
| `custom_rules` | Rule SecLang riêng của site (ID 1–99999, không được `Include` hay đọc file) |

### Anti-bot challenge (`bot_challenge`)

`{"enabled": true, "difficulty": 16, "ttl_sec": 3600, "exclude_paths": ["/api/"]}`

Trình duyệt phải giải một bài toán SHA-256 proof-of-work bằng JavaScript.
Đo trên Chromium với độ khó 16: 140–575 ms. Giải xong, trình duyệt nhận
cookie `hcw_bot` (HttpOnly, ký HMAC, gắn với site và IP; với IPv6 là gắn với
dải /64). Script, curl và bot không có JS engine sẽ bị chặn lại. Nonce chỉ
dùng được trong 5 phút, đúng site, đúng IP.

Dùng `exclude_paths` cho API, webhook và app mobile, vì các client này không
chạy được JS.

### Auth challenge (`auth`)

`{"enabled": true, "password": "…", "ttl_sec": 28800, "exclude_paths": []}`

- Mật khẩu được băm bcrypt ngay khi lưu; API chỉ trả về `password_hash`.
- Đổi mật khẩu thì mọi phiên đăng nhập cũ hết hiệu lực.
- Sai 10 lần trong 10 phút thì bị khoá 15 phút.
- Đăng xuất: `/.hcw/logout`.

Đường dẫn `/.hcw/` được engine dành riêng trên mọi site.

**Cluster:** đặt cùng một `challenge_secret_file` trên tất cả node. Khi DNS
chuyển khách sang node khác, khách không phải giải lại challenge.

Body nhị phân (octet-stream, ảnh, video, zip, pdf, gRPC) chỉ được kiểm tra
phần header, không quét nội dung. Với body JSON/form, engine kiểm tra
`body_limit_kb` đầu tiên, phần còn lại vẫn chuyển đủ lên upstream.

Gợi ý: bật `monitor` vài ngày để xem log, thêm `disabled_rules` cho các rule
chặn nhầm, rồi mới chuyển sang `block`.

### Bảo vệ HTML/JS động (`dynamic_protection`)

`{"html": true, "js": true, "paths": ["/san-pham/"]}`

**HTML:** mỗi trang trả về được thay bằng một trang nạp nhỏ chứa nội dung gốc
đã mã hoá bằng khoá ngẫu nhiên riêng cho từng response. Tên biến cũng thay đổi
mỗi lần. Trình duyệt giải mã rồi dựng lại toàn bộ tài liệu, gồm `<head>`, CSS,
script ngoài và script inline. Tool thu thập dữ liệu (curl, Scrapy,
BeautifulSoup…) chỉ nhận được một khối dữ liệu vô nghĩa, và mỗi lần tải lại
khác nhau.

**JavaScript:** file JS được bọc mã hoá. Khi chạy, mã gốc được đưa vào một thẻ
`<script>` mới, nên vẫn chạy đúng như cũ: biến toàn cục, `let`/`const`/`class`
ở cấp cao nhất và `"use strict"` đều giữ nguyên.

**Không áp dụng (giữ nguyên response)** khi gặp:

- response có CSP riêng (vì CSP sẽ chặn trang nạp);
- ES module (`import`/`export`);
- charset khác UTF-8, nén bằng brotli, body lớn hơn 4 MB;
- request khác GET, hoặc status khác 200.

Nội dung gzip từ upstream được tự giải nén. Response đã mã hoá gắn
`Cache-Control: no-store` và header `X-HCW-Protected`.

**Lưu ý:**

- Đây là **làm rối** (obfuscation), không phải mã hoá bảo mật: khoá đi kèm
  trang. Mục đích là tăng chi phí cho kẻ thu thập dữ liệu và phân tích mã,
  tương tự tính năng của SafeLine.
- Công cụ tìm kiếm có chạy JS (Googlebot) vẫn đọc được, nhưng nên giới hạn bằng
  `paths` cho khu vực cần bảo vệ (giá, nội dung độc quyền) để không ảnh hưởng
  SEO.
- Đã kiểm thử trên Chromium thật: tiêu đề, CSS, script ngoài/inline và tiếng
  Việt đều đúng, không có lỗi console.

### HTTPS tự động (Let's Encrypt)

Bật `acme.enabled` trong `waf.yaml`, rồi bật `auto_tls` cho site có cổng
`443_ssl`. Engine sẽ:

- tự xin chứng chỉ qua HTTP-01 (cổng 80) hoặc TLS-ALPN-01 (cổng 443), lưu ở
  `data_dir/acme` và tự gia hạn;
- chỉ xin chứng chỉ cho đúng tên miền của các site đã bật `auto_tls`, nên kẻ
  xấu không thể khiến node xin chứng chỉ cho tên miền khác.

Với cluster, Let's Encrypt giới hạn số chứng chỉ trùng lặp mỗi tuần. Từ khoảng
5 node trở lên, nên dùng chứng chỉ tải lên (`cert_id`) để đồng bộ cho mọi node.

HTTPS hỗ trợ cả HTTP/2.

### Chặn theo quốc gia (GeoIP)

Đặt `geoip_db` trong `waf.yaml` trỏ tới một file MMDB. Có thể dùng:

- **DB-IP Country Lite**: miễn phí, giấy phép CC BY 4.0, phải ghi nguồn
  db-ip.com. Cài nhanh bằng `install.sh node --geoip`.
- **MaxMind GeoLite2-Country**: cần tài khoản MaxMind.

Cập nhật database hằng tháng, rồi `systemctl kill -s HUP hcw-waf` để nạp lại
mà không phải restart.

Cách xử lý từng trường hợp:

| Trường hợp | Kết quả |
|---|---|
| IP thuộc quốc gia trong `country_deny` | 403 |
| Có `country_allow` và IP không thuộc danh sách | 403 |
| Có `country_allow` và không xác định được quốc gia | 403 |
| Chỉ có `country_deny` và không xác định được quốc gia (IP nội bộ, thiếu DB) | Cho qua |

Mỗi sự kiện tấn công đều ghi kèm mã quốc gia.

### Giám sát (Prometheus)

`GET /api/open/metrics`, xác thực bằng Bearer token. Các chỉ số gồm
`hcw_requests_total`, `hcw_blocked_total`, `hcw_rate_limited_total`,
`hcw_acl_blocked_total`, `hcw_bot_failed_total`, `hcw_monitored_total` (theo
từng site), cùng `hcw_sites` và `hcw_uptime_seconds`.

```yaml
scrape_configs:
  - job_name: hcw-waf
    scheme: https
    tls_config: {insecure_skip_verify: true}
    authorization: {credentials_file: /etc/prometheus/hcw.token}
    metrics_path: /api/open/metrics
    static_configs: [{targets: ["10.0.0.11:9443", "10.0.0.12:9443"]}]
```

## Console web quản trị

Console có sẵn trong `hcw-waf`, chạy cùng địa chỉ với API
(`https://127.0.0.1:9443/`). Đăng nhập bằng API token. Chức năng:

- **Tổng quan:** số request và số lần chặn trong 60 phút, biểu đồ theo phút,
  các loại tấn công gần đây, thống kê theo từng ứng dụng.
- **Ứng dụng:** thêm, sửa, xoá; cấu hình đủ chế độ CRS, rate limit, ACL,
  anti-bot, mật khẩu, HTTPS và các tuỳ chọn proxy.
- **Sự kiện tấn công:** lọc theo ứng dụng, xem chi tiết rule đã khớp. Có nút
  **Chặn IP** (thêm IP vào denylist) và **Báo chặn nhầm** (tắt các rule đã
  khớp cho site đó).
- **Chứng chỉ:** tải lên chứng chỉ PEM; cảnh báo khi sắp hết hạn.

Tên, màu và logo theo phần `brand` trong cấu hình (whitelabel). Console
dùng CSP chặt, không có script inline, và chèn mọi dữ liệu qua `textContent`
để tránh XSS.

Mặc định console chỉ nghe ở `127.0.0.1`. Muốn truy cập từ xa, có hai cách:
dùng SSH tunnel, hoặc đặt `api.listen: 0.0.0.0:9443` kèm `api.allow` giới
hạn IP được vào.

![Tổng quan](images/console-dashboard.png)
![Sự kiện](images/console-events.png)
![Ứng dụng](images/console-site.png)

## API quản trị

Mặc định ở `https://127.0.0.1:9443`. Token gửi qua header `X-HCW-API-TOKEN`
hoặc `Authorization: Bearer`. Mọi phản hồi có dạng
`{"data": …, "err": null, "msg": ""}`.

| Method | Path | Body |
|---|---|---|
| GET | `/api/open/health` | – (không cần token) |
| GET / POST / PUT | `/api/open/site` | object Site (PUT phải có `id`) |
| DELETE | `/api/open/site` | `{"ids":[1,2]}` |
| GET / POST / PUT / DELETE | `/api/open/cert` | `{"crt": PEM, "key": PEM}` |
| GET | `/api/open/events?limit=100&site_id=1` | – |
| GET | `/api/open/stats` | – |
| GET | `/api/open/timeseries` | – (60 phút gần nhất) |
| GET | `/api/open/info` | – (version, số site) |
| GET | `/api/open/brand` | – (không cần token) |

Ví dụ:

```bash
TOKEN=$(cat /etc/hcw-waf/api.token)
curl -k -H "X-HCW-API-TOKEN: $TOKEN" -X POST https://127.0.0.1:9443/api/open/site -d '{
  "server_names": ["shop.example.vn"],
  "ports": ["80"],
  "upstreams": ["http://10.0.0.10:8080"],
  "rate_limit": {"requests": 300, "window_sec": 60, "block_sec": 300}
}'
```

## Chạy cluster

Dùng `cluster/examples/controller-hcw-engine.yaml` cho controller. Trên mỗi
node chạy `waf/deploy/compose.yaml` (engine + agent). Cấu hình tạo ở node
primary sẽ tự đồng bộ sang các node còn lại (tạo, sửa, xoá), còn DNS chỉ trả
về IP các node khỏe. Toàn bộ luồng này đã được chạy thử end-to-end với 2 node
thật.

## Đã kiểm thử

`go test -race ./...` gồm:

- chặn SQLi, XSS, path traversal và RCE ở cả query lẫn body JSON/form;
- request hợp lệ có tiếng Việt và upload 3 MB đều đi qua;
- chế độ monitor;
- rate limit, ACL, wildcard host;
- `X-Forwarded-For` chỉ được tin khi đi qua proxy tin cậy;
- failover upstream;
- TLS nhiều chứng chỉ theo SNI;
- CRUD API và lưu trữ.
