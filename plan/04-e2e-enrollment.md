# 04 – Bộ e2e dùng enrollment token

**Trạng thái:** chưa làm. **Ưu tiên:** trung bình. **Code:** `e2e/`.

Hiện `e2e/` vẫn dùng `node_token` (kiểm tra tương thích ngược). Thêm kịch bản:
tạo token qua `POST /v1/enroll-tokens`, agent đăng ký, heartbeat dùng secret
riêng, token dùng lại bị 401, `require_enrollment: true` từ chối token chung,
xoá node thu hồi secret. Giữ một kịch bản dùng token chung.

Hoàn thành khi `HCW_E2E=1 go test -race ./...` trong `e2e/` xanh hai lần liên
tiếp và job `e2e` của CI xanh.
