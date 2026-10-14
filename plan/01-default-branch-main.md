# 01 – Đặt `main` làm nhánh mặc định

**Trạng thái:** cần quản trị viên repo (công cụ tự động không có quyền đổi).
**Ưu tiên:** cao.

## Bối cảnh
`main` đã chứa toàn bộ code (CI chạy trên `main`, release build từ `main`).
Nhánh mặc định trên GitHub vẫn là `hitechcloud/sweet-curie-uocch1`, nên trang
repo, Dependabot và PR mới vẫn nhắm nhánh đó.

## Việc cần làm
1. GitHub → repo → **Settings → General → Default branch** → bấm biểu tượng
   ⇄ → chọn `main` → *Update* → xác nhận.
2. (Tuỳ chọn) **Settings → Branches → Add rule** cho `main`: bắt buộc CI xanh
   (các job `test`, `vulncheck`, `helm`, `e2e`) trước khi merge.
3. Đóng/xoá nhánh `hitechcloud/sweet-curie-uocch1` khi không còn dùng.
4. Kiểm tra `.github/dependabot.yml` – Dependabot sẽ tự mở PR vào `main`.

## Hoàn thành khi
`git ls-remote --symref origin HEAD` trả `refs/heads/main`.
