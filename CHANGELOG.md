# Changelog

## Chưa phát hành

### Engine (`hcw-waf`) – hiệu năng và chống DoS
- **Giới hạn số tham số** (`max_args` theo site, mặc định 255) và độ sâu JSON
  (64): vượt thì trả 400 trước khi CRS chạy. Body JSON 1000 khoá: từ ~1,2 giây
  CPU còn ~1 ms; RAM đỉnh từ 2,3 GB còn 85 MB.
- **Giới hạn số WAF kiểm tra đồng thời** (`waf_concurrency`, mặc định
  2×GOMAXPROCS): chờ quá 10 giây hoặc khách bỏ đi thì trả 503.
- Đóng transaction Coraza ngay sau khi có kết luận (không giữ suốt thời gian
  proxy/stream); body được giữ bản sao và chuyển đủ cho upstream.
- **`static_fast_path`** (theo site, mặc định tắt): file tĩnh GET/HEAD không
  query chỉ chạy CRS phase 1 – CPU giảm ~74%.
- Bộ mã hoá bảo vệ HTML/JS động nhanh gấp ~3,5 lần, cấp phát ít hơn 8 lần
  (output không đổi).

### ⚠ Thay đổi cần lưu ý
- **`body_args_limit_kb`** (cấu hình node, mặc định 128 KB – giống
  ModSecurity): ở chế độ chặn, body JSON/form/XML lớn hơn bị trả **413**
  (sự kiện `body_limit`); chế độ giám sát chỉ kiểm tra 128 KB đầu. Site nhận
  JSON lớn: tăng `body_args_limit_kb` trong `waf.yaml` hoặc dùng rule
  `skip_waf` cho đường dẫn đó.

## v0.6.0 – 2026-10-14

### Engine (`hcw-waf`)
- **Trang Sự kiện**: lọc theo ứng dụng, loại, hành động, IP/CIDR, nội dung,
  khoảng thời gian, rule, quốc gia; xuất CSV/JSON (chống chèn công thức
  Excel, có ghi audit); bảng Top IP/URI/rule/quốc gia/loại; **chặn IP trên
  mọi ứng dụng** bằng 1 click (`POST /api/open/site/ip-deny`).
- Test bắt buộc mọi chuỗi giao diện đều có bản dịch tiếng Anh.

### Cluster (`hcw`)
- **Đăng ký node bằng token dùng một lần**: mỗi node có secret riêng gắn
  với ID node (controller chỉ lưu hash), thu hồi/đổi secret, tạo token trên
  dashboard; `install.sh agent --enroll-token-file`. Token dùng chung vẫn
  chạy (có cảnh báo) cho tới khi bật `require_enrollment: true`.

### Kiểm thử
- Bộ kiểm thử đầu-cuối `e2e/` (2 engine, controller, agent, DNS, hcwctl)
  chạy trong CI.

### Công cụ & tài liệu
- **MCP server cho `hcw-waf`** (`mcp_server/`): 11 công cụ đọc, 6 công cụ ghi
  (đổi chế độ site, chặn/bỏ chặn IP, tắt/bật rule, xoá cache), chế độ chỉ
  đọc, stdio cho Claude Desktop/Code, dữ liệu do kẻ tấn công kiểm soát được
  đánh dấu `untrusted`; image `ghcr.io/hitechcloud-vietnam/hitechcloud-waf-mcp`.
- **Hướng dẫn triển khai chi tiết** `docs/deploy.vi.md`; `PLAN.md` và `plan/`
  cho các việc còn lại.
- Issue template và workflow image MCP không còn trỏ về dự án gốc.

## v0.5.0 – 2026-10-14

### Bảo mật (từ đợt rà soát code)
- Chặn vượt WAF bằng đường dẫn không chuẩn (`/static/../login`, `//admin`,
  `%2e%2e`, `\`): trả 400 trước khi xét rule.
- `X-Forwarded-For` nhiều dòng không còn giả mạo được IP khách.
- Tài khoản `viewer` không còn đọc được private key, hash mật khẩu site và
  danh sách người dùng.
- `custom_rules` chỉ nhận directive rule; cấm operator đọc file/mạng.
- Sửa open redirect sau trang mật khẩu; rate limit IPv6 theo /64, giới hạn
  bộ nhớ; redirect HTTPS chỉ tới tên miền của site; token Telegram không lộ
  trong log.
- Đổi mật khẩu kết thúc các phiên khác; giới hạn đăng nhập theo tài khoản;
  giới hạn số phép bcrypt chạy đồng thời.
- Cluster: chống SSRF qua probe, node không đổi được địa chỉ đã đăng ký,
  agent chỉ đồng bộ collection cấu hình, DNS server bắt buộc https.
- `install.sh` kiểm tra SHA256 của binary, nhận token từ file.

### Engine (`hcw-waf`)
- **Cache response** trong RAM theo site (đuôi file tĩnh hoặc theo đường
  dẫn), `X-HCW-Cache`, xoá cache qua API/console; **nén gzip**.
- **Cân bằng tải**: round_robin, weighted (`weight=N`), least_conn,
  ip_hash, random; **sticky session**; sửa header request/response, ẩn
  `Server`/`X-Powered-By`.
- **Threat intelligence**: tự tải danh sách IP xấu (FireHOL, Spamhaus
  DROP…), chế độ block/challenge/monitor theo site, dùng được khi offline.
- **Bot tìm kiếm đã xác minh** (Googlebot, Bingbot…) qua reverse DNS được
  miễn anti-bot challenge.
- **Console song ngữ** Việt/Anh.
- Nâng Go lên 1.26, `golang.org/x/crypto` v0.58.0.

### Cluster (`hcw`)
- **GeoDNS** theo quốc gia/châu lục (mmdb), quy tắc theo pool hoặc bản ghi.
- **Bản ghi DNS tĩnh** A, AAAA, CNAME, TXT, MX, NS, SRV, CAA, wildcard,
  delegation; quản lý qua API `/v1/dns/records` và dashboard.
- Header token mặc định tới engine là `X-HCW-API-TOKEN` (engine image cũ cần
  đặt `token_header: X-SLCE-API-TOKEN`).

### Công cụ & triển khai
- **`hcwctl`**: CLI quản trị (site, chứng chỉ, sự kiện, backup/restore,
  người dùng…), bản Linux/macOS/Windows trong release.
- **Helm chart** và manifest Kubernetes (`deploy/`), kiểm tra trong CI.
- **Đặc tả OpenAPI 3.1** cho API engine và controller, test chống lệch.
- Tài liệu tiếng Anh (`README.en.md`, `docs/en/`).
- Bộ benchmark `bench/` và báo cáo hiệu năng.
- Nâng GitHub Actions (checkout, setup-go, docker/*), `miekg/dns`,
  `mcp-go`, `zap`.

## v0.4.0 – 2026-10-14

### Engine (`hcw-waf`)
- **Access log JSON** cho mọi request, xoay vòng theo dung lượng; trường
  `action` cho biết request được chuyển tiếp, bị chặn, bị challenge…
- **Audit log** mọi thao tác quản trị và đăng nhập, che thông tin bí mật;
  xem trên trang **Hệ thống**.
- **Sao lưu/khôi phục** toàn bộ cấu hình (site, chứng chỉ), kiểm tra hợp lệ
  trước khi áp dụng.
- **Health check upstream chủ động**: tự loại và đưa lại upstream theo trạng
  thái; hiển thị trên console.
- Kiểm thử WebSocket qua WAF.

## v0.3.0 – 2026-10-14

### Engine (`hcw-waf`)
- **Tài khoản console nhiều người dùng**: vai trò `admin`/`viewer`, mật khẩu
  bcrypt, phiên 12 giờ, khoá IP khi đăng nhập sai nhiều lần.
- **Xác thực 2 lớp TOTP** (Google/Microsoft Authenticator, Authy), bật bằng
  mã QR ngay trên console, chống dùng lại mã; admin có thể reset 2FA cho
  người khác.
- **Rule theo đường dẫn**: `allow` (whitelist), `deny`, `skip_waf`,
  `rate_limit` (ví dụ giới hạn `POST /login`), có điều kiện theo method và IP;
  có trình soạn rule trên console.
- **Cảnh báo Telegram và webhook** (ký HMAC), gom nhóm theo site và loại tấn
  công; có nút gửi thử.

## v0.2.0 – 2026-10-14

### Engine (`hcw-waf`)
- **Bảo vệ HTML/JS động** (`dynamic_protection`): HTML và JavaScript được mã
  hoá bằng khoá ngẫu nhiên riêng cho mỗi response; trình duyệt tự giải mã và
  hiển thị, còn bot không chạy JS chỉ nhận dữ liệu vô nghĩa. Không áp dụng
  cho trang có CSP, ES module, body lớn hơn 4 MB, hoặc charset khác UTF-8.
- **GeoIP**: `country_allow` / `country_deny` theo từng site; sự kiện ghi kèm
  quốc gia; nạp lại database bằng SIGHUP.
- **Let's Encrypt** tự động (`auto_tls`), HTTP/2, **HSTS**.
- **Rule SecLang tuỳ chỉnh** theo từng site, kiểm tra cú pháp trước khi lưu.
- **Metrics Prometheus** (`/api/open/metrics`) và thống kê theo phút
  (`/api/open/timeseries`).
- Console: thêm các tuỳ chọn mới; `api.allow` giới hạn IP được vào console.
- Sửa lỗi: rule tuỳ chỉnh (ID < 900000) bị loại khỏi log sự kiện.

### Cluster (`hcw`)
- Thống kê request/chặn và sự kiện tấn công **tập trung từ mọi node** về
  controller (`GET /v1/events`, hiển thị trên dashboard).
- Nâng `golang.org/x/net` lên v0.58.0 (bản cũ có lỗ hổng mức trung bình).

### Phát hành & vận hành
- `install.sh`: cài 1 lệnh cho node, agent, controller, DNS bằng systemd;
  tuỳ chọn `--geoip`.
- Workflow release (tag hoặc chạy tay), CI có govulncheck, Dependabot.

## v0.1.0 – 2026-10-14

Bản phát hành đầu tiên của nền tảng HiTechCloud WAF độc lập:

- Engine: OWASP Coraza + Core Rule Set v4, rate limit, ACL IP, anti-bot
  (proof-of-work), bảo vệ bằng mật khẩu, TLS theo SNI, failover upstream,
  trang chặn whitelabel, API quản trị.
- Console web quản trị whitelabel.
- Cluster nhiều node: controller, agent đồng bộ cấu hình, DNS authoritative
  có kiểm tra sức khỏe, ưu tiên region, failover.
