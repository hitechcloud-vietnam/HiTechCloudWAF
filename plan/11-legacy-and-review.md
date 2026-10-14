# 11 – Mã kế thừa và rà soát bảo mật còn thiếu

**Trạng thái:** chưa làm. **Ưu tiên:** trung bình.

- `management/` (tcontrollerd kế thừa) và `sdk/` (plugin Ingress-NGINX, Kong,
  lua-resty-t1k) **chưa được rà soát bảo mật**; quyết định giữ, viết lại hay
  bỏ khỏi repo.
- `compose.yaml` + `scripts/manage.py` ở gốc dùng image engine của bên thứ ba
  (cần thoả thuận OEM, xem `docs/LICENSING.vi.md`) – cân nhắc chuyển vào thư
  mục `legacy/`.
- Tên kế thừa còn lại có chủ ý: header `X-SLCE-API-TOKEN` (chỉ cho engine image
  cũ), tiền tố `slmcp_` (xem việc 08).
- Chạy lại rà soát bảo mật toàn bộ sau v0.6.0 (cache, cân bằng tải, threat
  intel, enrollment, MCP, trang Sự kiện là code mới).
