# hcwbench – benchmark tái lập được cho engine HiTechCloud WAF

`bench/` là một Go module riêng (`github.com/hitechcloud-vietnam/HiTechCloudWAF/bench`,
chỉ dùng thư viện chuẩn). Công cụ `cmd/hcwbench` đo engine `hcw-waf` **từ bên ngoài**,
đúng như khi chạy thật: chạy file nhị phân, tạo site qua API quản trị HTTPS rồi
bắn tải HTTP vào cổng site.

Kết quả và phân tích: [RESULTS.md](RESULTS.md).

## Yêu cầu

- Linux (đọc `/proc/<pid>/stat`, `/proc/<pid>/status`, `/proc/cpuinfo`).
- Go ≥ 1.25 (hoặc `GOTOOLCHAIN=auto` để Go tự tải toolchain).
- Không bắt buộc: `taskset` (util-linux) để ghim CPU, giúp số liệu ổn định hơn.
- Các cổng trống trên 127.0.0.1: `19700` (API), `18200` (site), `18201` (upstream).

## Chạy nhanh

```sh
# 1. Build engine
cd waf && go build -o /tmp/hcwwaf ./cmd/hcw-waf && cd ..

# 2. Chạy toàn bộ kịch bản (~4 phút trên máy 4 vCPU)
cd bench && go run ./cmd/hcwbench -waf /tmp/hcwwaf -json /tmp/hcwbench.json
```

Bảng Markdown in ra stdout, tiến độ in ra stderr; `-json` ghi thêm số liệu thô.

## Công cụ làm gì

1. Khởi động một **upstream trong tiến trình** (Go `net/http`) trả trang HTML cố định
   1 KB (mọi đường dẫn) và 50 KB (`/page50k`), đếm số kết nối TCP mới nhận được.
2. Với **mỗi kịch bản**, chạy một tiến trình `hcw-waf` mới với thư mục dữ liệu tạm và
   file cấu hình tạm (`data_dir`, `bind: 127.0.0.1`, `api.listen`, token ngẫu nhiên),
   chờ `GET /api/open/health`, rồi tạo site bằng `POST /api/open/site`
   (header `X-HCW-API-TOKEN`). Thời gian trả về của POST được ghi lại làm
   **thời gian Apply** (API áp cấu hình đồng bộ; lần đầu có biên dịch OWASP CRS).
3. Gửi một request kiểm tra (đúng mã trạng thái mong đợi; kịch bản 7 còn kiểm tra
   header `X-HCW-Protected: html`) – kịch bản sai sẽ dừng ngay, không đo số liệu vô nghĩa.
4. Chạy **tải vòng kín**: `-c` client keep-alive, mỗi client gửi request, đọc hết
   phản hồi rồi gửi tiếp. Khởi động `-warmup` (không tính), sau đó đo trong `-d`.
5. Ghi: req/s, độ trễ p50/p90/p99/max, tỉ lệ lỗi (lỗi kết nối hoặc mã trạng thái khác
   mong đợi), CPU của engine (utime+stime trong `/proc/<pid>/stat`, lấy mẫu đúng ở đầu và
   cuối cửa sổ đo), RSS (`VmRSS`) lúc nghỉ và cuối, RSS đỉnh (`VmHWM`), số kết nối
   upstream mới.
6. Dừng engine bằng SIGTERM (SIGKILL sau 5 giây), xoá thư mục tạm.

## Kịch bản

| # | Mô tả |
|---|---|
| 1 | Gọi thẳng upstream, không qua WAF (mức nền) |
| 2 | Site `mode: off` – proxy thuần |
| 3 | `mode: block`, paranoia 1, GET có query string 5 tham số, header giống trình duyệt (UA, Accept*, Cookie 3 giá trị, Referer) |
| 4 | Như 3 nhưng `POST /api/orders` JSON ~2 KB (khoảng 100 trường) |
| 4b | Như 4 nhưng body JSON phẳng 1 000 khoá (~28 KB). Engine có giới hạn số tham số trả 400; bản cũ trả 200 (cả hai đều được chấp nhận) |
| 5 | Như 3 với paranoia 2 |
| 6 | PL1, request tấn công SQLi (`UNION SELECT`) – mong đợi 403 |
| 7 | PL1 + `dynamic_protection: {html: true}`, trang 50 KB |
| 7a | PL1, trang 50 KB, không dynamic – đối chứng của 7 |
| 9 | PL1, `GET /assets/css/app.css` (file tĩnh, không query), header trình duyệt |
| 9a | Như 9 với `static_fast_path: true` (chỉ chạy CRS phase 1) |
| 8 | 200 site PL1 cùng cổng, tải chia vòng tròn qua 200 tên miền (chi phí định tuyến, thời gian Apply khi tạo lần lượt 200 site) |

## Tham số

| Cờ | Mặc định | Ý nghĩa |
|---|---|---|
| `-waf` | `/tmp/hcwwaf` | đường dẫn file nhị phân `hcw-waf` |
| `-c` | `32` | số client đồng thời |
| `-d` | `20s` | thời gian đo mỗi kịch bản |
| `-warmup` | `3s` | khởi động trước khi đo |
| `-settle` | `2s` | nghỉ sau khi cấu hình xong (GC sau biên dịch CRS) |
| `-only` | (tất cả) | chỉ chạy một số kịch bản, ví dụ `-only 3,6` |
| `-sites` | `200` | số site của kịch bản 8 |
| `-waf-cpus` / `-bench-cpus` | `auto` | danh sách CPU cho `taskset`; `auto` = engine nửa đầu, hcwbench nửa sau; `""` = không ghim |
| `-waf-procs` / `-bench-procs` | theo số CPU được ghim | `GOMAXPROCS` của engine / của hcwbench |
| `-api`, `-port`, `-upstream` | `127.0.0.1:19700`, `18200`, `127.0.0.1:18201` | địa chỉ API, cổng site, địa chỉ upstream |
| `-json` | – | ghi kết quả thô dạng JSON |
| `-keep` | `false` | giữ thư mục tạm (log engine, cấu hình) |
| `-site-extra` | – | JSON trộn vào mọi site (thí nghiệm), ví dụ `'{"disabled_rules":[942100]}'` |
| `-minimal-headers` | `false` | chỉ gửi `User-Agent` và `Accept` (thí nghiệm ảnh hưởng của header/cookie) |

Biến môi trường của hcwbench được truyền cho engine, nên có thể bật thêm chẩn đoán
của Go runtime, ví dụ xem GC của engine:

```sh
GODEBUG=gctrace=1 go run ./cmd/hcwbench -only 4 -keep   # log GC nằm trong engine.log ở thư mục tạm
```

## Đọc kết quả cho đúng

- **CPU µs/req** là chỉ số ổn định nhất (lệch < 5 % giữa các lần chạy). req/s và độ trễ
  phụ thuộc vào việc máy có đang bận việc khác hay không – xem `loadavg` in ở đầu/cuối
  và cột "CPU engine (lõi)": nếu thấp hơn hẳn `GOMAXPROCS` của engine trong kịch bản
  có WAF thì engine đã bị tranh CPU.
- Tải vòng kín với 32 client trên 2 lõi: khi engine bão hoà CPU, độ trễ ≈ số client ÷
  req/s (thời gian xếp hàng), không phải thời gian xử lý một request.
- Load generator và upstream chạy chung tiến trình hcwbench; kịch bản 1 thường bị giới
  hạn bởi chính hcwbench (xem trường `BenchCPU` trong JSON).
- CPU được quy đổi từ tick với `USER_HZ = 100` (giá trị chuẩn của Linux x86-64/arm64).

## Kiểm tra mã nguồn

```sh
cd bench && gofmt -l . && go vet ./...
```
