# Kiểm thử end-to-end (e2e)

Module Go riêng (`github.com/hitechcloud-vietnam/HiTechCloudWAF/e2e`, chỉ dùng
thư viện chuẩn) chạy **toàn bộ nền tảng** trên máy local, không cần Docker và
không cần quyền root:

1. Build `hcw-waf` (`waf/`), `hcw` (`cluster/`) và `hcwctl` (`ctl/`) từ chính
   repo bằng `go build` vào thư mục tạm.
2. Sinh CA tự ký và chứng chỉ server (crypto/x509) cho `127.0.0.1`,
   `127.0.0.2`, `localhost`; dùng cho API của controller và của hai engine.
3. Khởi động trên các cổng cao ngẫu nhiên của loopback:

| Thành phần | Địa chỉ | Ghi chú |
|---|---|---|
| upstream HTTP nhỏ | `127.0.0.1:<ngẫu nhiên>` | chạy trong tiến trình test |
| engine **primary** | API `127.0.0.1:<A1>`, site bind `127.0.0.1` | nơi tạo site |
| engine **edge** | API `127.0.0.1:<A2>`, site bind `127.0.0.2` | node của cluster, IP "public" là `127.0.0.2` |
| `hcw controller` | `https://127.0.0.1:<C>` | `allow_loopback_nodes: true`, đồng bộ cấu hình từ primary mỗi 1s |
| `hcw agent` | – | cạnh engine edge, node `edge-1`, pool `web`, heartbeat 1s |
| `hcw dns` | `127.0.0.1:<D>` (UDP+TCP) | zone `e2e.test`, bản ghi pool `edge` → pool `web` |

Hai engine dùng chung cổng site (cấu hình site được nhân bản nguyên vẹn) nên
primary bind `127.0.0.1`, edge bind `127.0.0.2`.

## Kịch bản

Mỗi kịch bản là một subtest của `TestPlatform`:

- **site replicates to edge, proxies and blocks SQLi**: tạo site trên primary
  qua API → agent nhân bản sang edge; request tới edge với Host
  `shop.e2e.test` đến được upstream; request SQLi bị chặn 403, upstream không
  nhận được, engine edge ghi sự kiện `waf`.
- **event reaches the controller**: sự kiện đó xuất hiện ở `GET /v1/events`
  của controller (gắn `node: edge-1`).
- **dns pool answers the edge node**: `edge.e2e.test A` (truy vấn UDP bằng
  client DNS tối giản viết bằng thư viện chuẩn) trả về `127.0.0.2`.
- **dns static record from the controller**: tạo bản ghi qua
  `POST /v1/dns/records` (bản ghi sai cú pháp → 400) → DNS server phục vụ
  `www.e2e.test A 192.0.2.10` (trước đó là NXDOMAIN).
- **draining the node removes it from dns**: `PATCH /v1/nodes/edge-1
  {"drain":true}` → node biến mất khỏi câu trả lời DNS và khỏi
  `/v1/pools/web/endpoints`; bỏ drain → node quay lại.
- **hcwctl sites list and events with --ca**: `hcwctl login` không có `--ca`
  bị từ chối; với `--ca` thì `sites list` và `events` (bảng và `-o json`)
  chạy được trên primary.
- **path normalisation on the edge**: `/static/../admin`, `/static/./admin`,
  `/static//admin` → 400 (sự kiện `bad_path`), không tới upstream.

## Chạy local

Cần Go (toolchain 1.26 sẽ được tải tự động theo `go.mod` nếu bản cài đặt cũ
hơn) và Linux (macOS: xem bên dưới). Suite bị bỏ qua nếu không đặt
`HCW_E2E=1`, nên `go test ./...` thông thường không bị ảnh hưởng.

```bash
cd e2e
gofmt -l . && go vet ./...
HCW_E2E=1 go test -count=1 -v -timeout 8m ./...
```

Lần đầu (build cache trống) mất khoảng 1 phút để build ba binary; các lần sau
khoảng 10 giây.

Biến môi trường:

| Biến | Ý nghĩa |
|---|---|
| `HCW_E2E=1` | bật suite (bắt buộc) |
| `HCW_E2E_KEEP=1` | giữ lại thư mục làm việc (cấu hình, log, data) sau khi chạy để điều tra; đường dẫn được in ra |

Khi một kịch bản thất bại, test in phần cuối log của từng tiến trình
(primary, edge, controller, agent, dns) cùng access log của hai engine. Tiến
trình được dừng theo PID (SIGTERM, sau 5 giây thì SIGKILL) trong `t.Cleanup`.

**macOS**: loopback chỉ có `127.0.0.1`; thêm alias trước khi chạy
(`sudo ifconfig lo0 alias 127.0.0.2 up`), nếu không suite sẽ tự bỏ qua.

## CI

Job `e2e` trong `.github/workflows/ci.yml` chạy sau job `test`, với
`HCW_E2E=1`.
