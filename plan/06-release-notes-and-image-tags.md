# 06 – Release notes từ CHANGELOG và tag image theo phiên bản

**Trạng thái:** chưa làm. **Ưu tiên:** thấp–trung bình.
**Code:** `.github/workflows/release.yml`, `.github/workflows/ci.yml`, `.github/workflows/mcp-docker.yml`.

1. ~~Release workflow lấy ghi chú từ `CHANGELOG.md`~~ – **đã xong** (từ bản
   sau v0.6.0). Ghi chú của v0.6.0 trên GitHub vẫn là danh sách tự sinh: sửa tay
   (Releases → v0.6.0 → Edit → dán mục v0.6.0 của CHANGELOG).
2. Khi release, đẩy image GHCR với tag `vX.Y.Z` (hiện chỉ `latest` + SHA) cho
   `hitechcloud-waf`, `hitechcloud-waf-cluster`, `hitechcloud-waf-mcp`; Helm
   `image.tag` mặc định = `appVersion`.
3. Ký binary/checksum (cosign hoặc minisign) và hướng dẫn kiểm tra trong
   `docs/deploy.vi.md`.
