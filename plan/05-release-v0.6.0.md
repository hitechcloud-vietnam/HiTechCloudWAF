# 05 – Phát hành v0.6.0

**Trạng thái:** chờ (sau khi CI trên `main` xanh). **Ưu tiên:** cao.

## Nội dung
Mục *Chưa phát hành* trong `CHANGELOG.md`: trang Sự kiện, đăng ký node, e2e,
MCP server cho hcw-waf, hướng dẫn triển khai chi tiết (+ việc 02 nếu kịp).

## Các bước
1. Đổi tiêu đề *Chưa phát hành* thành `v0.6.0 – <ngày>` trong `CHANGELOG.md`,
   commit vào `main`, đợi CI xanh.
2. Actions → **Release** → *Run workflow* trên `main`, `version = v0.6.0`
   (đẩy tag trực tiếp cũng được nếu có quyền).
3. Kiểm tra release có: `hcw-waf-linux-{amd64,arm64}`, `hcw-linux-{amd64,arm64}`,
   `hcwctl-{linux,darwin}-{amd64,arm64}`, `hcwctl-windows-amd64.exe`,
   `install.sh`, `SHA256SUMS`.
4. Sửa phần mô tả release: dán mục v0.6.0 của CHANGELOG (việc 06 sẽ tự động hoá).
