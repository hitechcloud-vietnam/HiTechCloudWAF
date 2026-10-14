# Kế hoạch phát triển HiTechCloud WAF

Cập nhật: 2026-10-14. Nhánh chính: **`main`** (mọi thay đổi merge vào đây; CI
phải xanh). Phiên bản phát hành mới nhất: **v0.5.0**.

Mỗi việc chưa xong có một file riêng trong [`plan/`](plan/) mô tả bối cảnh,
file code liên quan, các bước và tiêu chí hoàn thành. Dev nhận việc: ghi tên
mình vào dòng *Trạng thái* của file, làm trên nhánh riêng, merge vào `main` khi
CI xanh, rồi chuyển việc sang mục *Đã xong* bên dưới (và xoá file trong
`plan/`).

## Việc chưa xong (theo thứ tự ưu tiên)

| # | Việc | Ưu tiên | Ghi chú |
|---|---|---|---|
| [01](plan/01-default-branch-main.md) | Đặt `main` làm nhánh mặc định trên GitHub | cao | cần quyền admin repo |
| [02](plan/02-engine-performance.md) | Tối ưu hiệu năng engine (giới hạn tham số, semaphore, đóng transaction sớm, fast path tĩnh, mã hoá dynamic) | cao | đang làm dở |
| [05](plan/05-release-v0.6.0.md) | Phát hành v0.6.0 | cao | sau khi CI xanh |
| [03](plan/03-helm-enrollment.md) | Helm chart + bootstrap Docker hỗ trợ enrollment token | trung bình | |
| [04](plan/04-e2e-enrollment.md) | Bộ e2e dùng enrollment token | trung bình | |
| [09](plan/09-engine-followups.md) | Engine: health check `last_error`, gộp request cache, timeout listener… | trung bình | 7 mục |
| [10](plan/10-cluster-followups.md) | Cluster/DNS: lưu bản ghi DNS xuống đĩa, test dashboard, HA controller, DNSSEC… | trung bình | 6 mục |
| [11](plan/11-legacy-and-review.md) | Mã kế thừa (`management/`, `sdk/`) và rà soát bảo mật lần 2 | trung bình | |
| [06](plan/06-release-notes-and-image-tags.md) | Release notes từ CHANGELOG, tag image theo phiên bản, ký binary | thấp–TB | |
| [08](plan/08-mcp-followups.md) | MCP server: dùng API chặn IP mới, tra sự kiện theo ID, đổi tiền tố token | thấp | |
| [07](plan/07-docs-english.md) | Bản tiếng Anh của tài liệu mới | thấp | |

## Đã xong

- Engine `hcw-waf`: OWASP Coraza + CRS v4, chế độ block/monitor/off, paranoia,
  rate limit, rule theo đường dẫn, ACL IP, GeoIP, anti-bot, mật khẩu site,
  bảo vệ HTML/JS động, TLS SNI, Let's Encrypt, HSTS, rule SecLang, cache +
  gzip, cân bằng tải (5 thuật toán) + sticky + sửa header, health check chủ
  động, threat intelligence, bot đã xác minh, cảnh báo Telegram/webhook,
  Prometheus, access log, audit log, sao lưu/khôi phục.
- Console song ngữ, nhiều tài khoản, vai trò admin/viewer, 2FA TOTP, trang
  Sự kiện có lọc/xuất/top/chặn IP mọi site.
- Cluster: controller, agent, DNS authoritative có health check, GeoDNS, bản
  ghi tĩnh, đồng bộ cấu hình, sự kiện tập trung, đăng ký node bằng token dùng
  một lần + secret riêng.
- Công cụ: `hcwctl`, MCP server cho hcw-waf, Helm chart + manifest K8s, đặc tả
  OpenAPI + test chống lệch, bộ benchmark, bộ e2e, installer 1 lệnh có kiểm
  tra SHA256.
- Bảo mật: đợt rà soát code (3 lỗi Cao, 5 Trung bình, 8 Thấp) đã sửa kèm test.
- Phát hành v0.1.0 → v0.5.0; CI: test + race, govulncheck, helm, e2e, image GHCR.
- Tài liệu: [docs/deploy.vi.md](docs/deploy.vi.md) (triển khai chi tiết),
  engine, cluster, Kubernetes, API, tiếng Anh.

## Quy ước cho dev

- Go: `gofmt`, `go vet ./...`, `go test -race ./...` trong module đã sửa
  (`waf/`, `cluster/`, `ctl/`, `bench/`, `mcp_server/`, `e2e/` với
  `HCW_E2E=1`). CI dùng bản vá mới nhất của Go 1.26.
- Đổi API: cập nhật `docs/api/*.openapi.yaml` (test sẽ báo nếu thiếu route).
- Chuỗi giao diện console: luôn qua `t()` và có bản dịch trong `i18n.js`
  (test `waf/internal/console/i18n_test.go`).
- Whitelabel: không đưa tên/thương hiệu bên thứ ba vào giao diện, log, tài liệu
  người dùng (trừ phần ghi nhận giấy phép trong `NOTICE.md`,
  `docs/LICENSING.vi.md`).
- Ghi thay đổi vào mục *Chưa phát hành* của `CHANGELOG.md`.
