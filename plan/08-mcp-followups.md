# 08 – MCP server: việc còn lại

**Trạng thái:** chưa làm. **Ưu tiên:** thấp. **Code:** `mcp_server/`.

1. `add_denied_ips`: dùng `POST /api/open/site/ip-deny` (một request, không
   ghi đè sửa đổi đồng thời trên console); giữ đường đọc-sửa-ghi cho node cũ.
2. Engine: thêm `GET /api/open/events/{id}` để `get_attack_event` không phải
   quét 1000 sự kiện mới nhất (nhớ cập nhật `docs/api/waf.openapi.yaml` – test
   chống lệch).
3. Đổi tiền tố bearer token MCP `slmcp_` sang `hcwmcp_` (giữ chấp nhận tiền tố
   cũ một thời gian; sửa test).
4. Image: workflow `mcp-docker.yml` đẩy `ghcr.io/hitechcloud-vietnam/hitechcloud-waf-mcp`;
   bổ sung hướng dẫn chạy bằng Docker trong `mcp_server/README.md`.
