# 09 – Engine: lỗi nhỏ và cải tiến đã ghi nhận

**Trạng thái:** chưa làm. **Code:** `waf/`.

| # | Việc | Ưu tiên |
|---|---|---|
| 1 | Health check: upstream báo *khỏe* nhưng `last_error` vẫn là "connection refused" (thấy khi chạy MCP live). Xem `proxy/health.go` – xoá `lastError` khi thành công hoặc tách "lỗi gần nhất" khỏi trạng thái. | trung bình |
| 2 | Cache: gộp request trùng khi miss (request coalescing / singleflight) tránh dồn tải về origin. | trung bình |
| 3 | Listener: thêm `ReadTimeout`/giới hạn số kết nối đồng thời (chống slow-body); hiện chỉ có `ReadHeaderTimeout`/`IdleTimeout`. Cẩn thận upload lớn và WebSocket. | trung bình |
| 4 | Metric `hcw_acl_blocked_total`: cập nhật mô tả (đã gồm threat intel). | thấp |
| 5 | Threat intel: đọc định dạng JSON của Spamhaus (`drop_v4.json`); API ép tải lại feed. | thấp |
| 6 | Trang Sự kiện: tự làm mới; tab Quốc gia mới chỉ thử khi không có GeoIP. | thấp |
| 7 | Restore cấu hình: hiện ghi store trước rồi mới `Apply`; nên áp thử trước khi ghi. | thấp |
| 8 | Console: thêm trường `max_args`, `static_fast_path` vào form site (kèm bản dịch `i18n.js`). | trung bình |
| 9 | `body_args_limit_kb` theo từng site (hiện chỉ cấu hình node); giới hạn riêng cho multipart (trường text đang tính vào `body_limit_kb`). | trung bình |
| 10 | Helm `values.yaml` / `deploy/kubernetes`: thêm `body_args_limit_kb`, `waf_concurrency` vào cấu hình mẫu. | thấp |
