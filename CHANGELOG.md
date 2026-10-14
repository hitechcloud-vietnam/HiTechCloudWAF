# Changelog

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
