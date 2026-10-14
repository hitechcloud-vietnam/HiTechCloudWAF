# HiTechCloud WAF Engine (`waf/`)

Engine WAF riêng của HiTechCloud, mã nguồn mở hoàn toàn, **không phụ thuộc
image của Chaitin**. Binary: `hcw-waf`.

## Luồng xử lý một request

```
Client ─► listener (HTTP / HTTPS theo SNI)
          │
          ├─ chọn site theo Host (tên chính xác, wildcard *.domain, hoặc "_")
          ├─ redirect HTTPS (tuỳ chọn)
          ├─ ACL IP: ip_deny → 403, ip_allow (nếu có) → 403
          ├─ Rate limit theo IP/site → 429 + thời gian chặn
          ├─ OWASP Coraza + Core Rule Set v4 (SQLi, XSS, RCE, LFI/RFI,
          │   path traversal, scanner, protocol attack…) → 403
          └─ Reverse proxy → upstream (round-robin; upstream lỗi bị loại 10s)
```

Trang chặn mang thương hiệu HiTechCloud và hiển thị **Event ID** để tra cứu.
Mỗi lần chặn sinh một sự kiện, lưu trong bộ nhớ và ghi vào file JSONL.

## Chế độ bảo vệ của từng site

| Trường | Ý nghĩa |
|---|---|
| `mode` | `block` (chặn), `monitor` (chỉ ghi log), `off` (proxy thuần) |
| `paranoia` | 1–4. Mặc định 1, ít chặn nhầm. PL3–4 bắt được nhiều hơn nhưng cần tinh chỉnh |
| `anomaly_threshold` | Ngưỡng điểm CRS để chặn (mặc định 5) |
| `disabled_rules` | Danh sách ID rule CRS tắt cho site, dùng khi bị chặn nhầm |
| `rate_limit` | `{requests, window_sec, block_sec}` |
| `ip_allow` / `ip_deny` | Danh sách IP hoặc CIDR |
| `ports` | `"80"`, `"443_ssl"` (cổng `_ssl` bắt buộc có `cert_id`) |
| `upstreams` | `http(s)://host:port`, có thể nhiều upstream |
| `upstream_host`, `upstream_insecure`, `redirect_https` | Tuỳ chọn proxy |

Body nhị phân (octet-stream, ảnh, video, zip, pdf, gRPC) chỉ được kiểm tra
phần header, không quét nội dung. Với body JSON/form, engine kiểm tra
`body_limit_kb` đầu tiên, phần còn lại vẫn chuyển đủ lên upstream.

Gợi ý: bật `monitor` vài ngày để xem log, thêm `disabled_rules` cho các rule
chặn nhầm, rồi mới chuyển sang `block`.

## API quản trị

Mặc định ở `https://127.0.0.1:9443`. Token gửi qua header `X-HCW-API-TOKEN`
hoặc `Authorization: Bearer`. Mọi phản hồi có dạng
`{"data": …, "err": null, "msg": ""}`.

| Method | Path | Body |
|---|---|---|
| GET | `/api/open/health` | – (không cần token) |
| GET / POST / PUT | `/api/open/site` | object Site (PUT phải có `id`) |
| DELETE | `/api/open/site` | `{"ids":[1,2]}` |
| GET / POST / PUT / DELETE | `/api/open/cert` | `{"crt": PEM, "key": PEM}` |
| GET | `/api/open/events?limit=100&site_id=1` | – |
| GET | `/api/open/stats` | – |

Ví dụ:

```bash
TOKEN=$(cat /etc/hcw-waf/api.token)
curl -k -H "X-HCW-API-TOKEN: $TOKEN" -X POST https://127.0.0.1:9443/api/open/site -d '{
  "server_names": ["shop.example.vn"],
  "ports": ["80"],
  "upstreams": ["http://10.0.0.10:8080"],
  "rate_limit": {"requests": 300, "window_sec": 60, "block_sec": 300}
}'
```

## Chạy cluster

Dùng `cluster/examples/controller-hcw-engine.yaml` cho controller. Trên mỗi
node chạy `waf/deploy/compose.yaml` (engine + agent). Cấu hình tạo ở node
primary sẽ tự đồng bộ sang các node còn lại (tạo, sửa, xoá), còn DNS chỉ trả
về IP các node khỏe. Toàn bộ luồng này đã được chạy thử end-to-end với 2 node
thật.

## Đã kiểm thử

`go test -race ./...` gồm:

- chặn SQLi, XSS, path traversal và RCE ở cả query lẫn body JSON/form;
- request hợp lệ có tiếng Việt và upload 3 MB đều đi qua;
- chế độ monitor;
- rate limit, ACL, wildcard host;
- `X-Forwarded-For` chỉ được tin khi đi qua proxy tin cậy;
- failover upstream;
- TLS nhiều chứng chỉ theo SNI;
- CRUD API và lưu trữ.
