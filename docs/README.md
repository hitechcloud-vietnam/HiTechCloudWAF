# Tài liệu HiTechCloud WAF

English: [README.en.md](../README.en.md) · [en/](en/)

## Bắt đầu từ đâu?

| Bạn muốn… | Đọc |
|---|---|
| Cài thử nhanh một node | [install.vi.md](install.vi.md) |
| Triển khai production từng bước (một node, Docker, Kubernetes, cluster + DNS, bảo mật, giám sát, sao lưu, nâng cấp, xử lý sự cố) | [deploy.vi.md](deploy.vi.md) |
| Cấu hình website theo loại ứng dụng, đứng sau CDN/load balancer, runbook vận hành, checklist go-live | `docs/deploy/` (đang viết) |
| Triển khai tự động bằng Ansible | `docs/deploy/ansible.vi.md` (đang viết) |
| Chạy trên Kubernetes (Helm) | [kubernetes.vi.md](kubernetes.vi.md) |
| Hiểu mọi tuỳ chọn bảo vệ của site (CRS, rate limit, anti-bot, cache, cân bằng tải, threat intel…) | [engine.vi.md](engine.vi.md) |
| Hiểu kiến trúc cluster, DNS, GeoDNS, đăng ký node | [cluster.vi.md](cluster.vi.md) |
| Tự động hoá qua API | [api/README.md](api/README.md) (đặc tả OpenAPI 3.1) |
| Quản trị bằng dòng lệnh | [../ctl/README.md](../ctl/README.md) (`hcwctl`) |
| Kết nối trợ lý AI (MCP) | [../mcp_server/README.md](../mcp_server/README.md) |
| Đo hiệu năng | [../bench/README.md](../bench/README.md), [../bench/RESULTS.md](../bench/RESULTS.md) |
| Kiểm thử đầu-cuối | [../e2e/README.md](../e2e/README.md) |
| Giấy phép | [LICENSING.vi.md](LICENSING.vi.md), [../NOTICE.md](../NOTICE.md) |

## Dành cho người phát triển

- Kế hoạch và việc còn lại: [../PLAN.md](../PLAN.md), [../plan/](../plan/)
- Lịch sử thay đổi: [../CHANGELOG.md](../CHANGELOG.md)
- Quy ước: mỗi module Go chạy `gofmt`, `go vet ./...`, `go test -race ./...`;
  đổi API thì cập nhật `docs/api/*.openapi.yaml`; chuỗi console phải có bản
  dịch trong `i18n.js`.

## Thành phần

```
hcw-waf      engine WAF + console + API (mỗi node)            waf/
hcw          controller | agent | dns | token | version        cluster/
hcwctl       CLI quản trị                                       ctl/
MCP server   cho trợ lý AI                                      mcp_server/
Helm chart   Kubernetes                                         deploy/helm/
install.sh   cài 1 lệnh (systemd)                               scripts/
```
