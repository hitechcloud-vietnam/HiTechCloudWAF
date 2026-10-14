# 10 – Cluster / DNS: việc còn lại

**Trạng thái:** chưa làm. **Code:** `cluster/`.

| # | Việc | Ưu tiên |
|---|---|---|
| 1 | DNS server lưu bản ghi tĩnh nhận từ controller xuống đĩa, để khởi động khi controller mất kết nối vẫn trả đủ. | trung bình |
| 2 | Dashboard controller: chưa có kiểm thử trình duyệt (Playwright) cho phần bản ghi DNS và đăng ký node. | trung bình |
| 3 | Controller HA (2 controller, state dùng chung hoặc sao chép). | trung bình |
| 4 | DNSSEC, zone transfer (AXFR/IXFR có TSIG) cho DNS phụ ngoài. | thấp |
| 5 | Bản ghi controller nhắm sub-zone thông qua zone cha. | thấp |
| 6 | Log "agent started" in hostname thay vì node ID trước lần đăng ký đầu (thẩm mỹ). | thấp |
| 7 | `install.sh`: khi chạy lại (nâng cấp) đang **ghi đè** `controller.yaml`, `agent.yaml`, `dns.yaml` từ mẫu, làm mất chỉnh sửa tay. Nên giữ file cũ (như `waf.yaml`), ghi bản mới thành `*.yaml.new` và in thông báo; thêm cờ `--force-config`. Cập nhật `docs/deploy.vi.md` mục nâng cấp + `docs/en/`. | cao |
