# Báo cáo hiệu năng engine HiTechCloud WAF (hcw-waf)

Đo bằng `bench/cmd/hcwbench` (cách chạy: [README.md](README.md)) trên commit
`0f17cd3` (v0.4.0 – "active upstream health checks"), ngày 14/10/2026.

## Tóm tắt

- **Proxy thuần (`mode: off`) rẻ**: ~120 µs CPU/request, ~12 700 req/s trên 2 lõi.
- **OWASP CRS chiếm gần như toàn bộ chi phí**: GET thường ở PL1 tốn **~3,1 ms CPU/request**
  (≈ 26 lần proxy thuần, ≈ 320 req/s mỗi lõi); 89 % trong số đó nằm ở các rule phát hiện
  (913–944). PL2 đắt hơn PL1 60–65 %.
- **Request có body nhiều trường là điểm yếu lớn nhất**: POST JSON 2 KB (~100 trường) tốn
  **~41 ms CPU/request** (≈ 24 req/s mỗi lõi) và đẩy RSS lên **~435 MB**. Chi phí tăng
  tuyến tính ~0,4 ms cho mỗi khoá JSON: một body 22 KB với 1 000 khoá tốn ~0,41 giây CPU.
- Dynamic protection thêm ~0,9 ms CPU/request trên trang 50 KB (+45 %) và làm phản hồi
  lớn thêm 35 %.
- Có 200 site thì chi phí định tuyến không đáng kể, nhưng số kết nối upstream tăng 6 lần
  (199 so với ~31) vì mỗi site dùng một `http.Transport` riêng.

## Máy đo

| Mục | Giá trị |
|---|---|
| CPU | Intel(R) Xeon(R) Processor @ 2.10GHz, `nproc` = 4 (máy ảo Firecracker) |
| RAM | 16 GB (16 479 424 kB) |
| Kernel | Linux 6.18.44-fc-v114, amd64 |
| Go | go1.25.0 (engine và hcwbench) |
| Engine | `/tmp/hcwwaf` build từ `waf/cmd/hcw-waf` (version `dev`), `GOMAXPROCS=2`, ghim CPU 0-1 bằng `taskset` |
| hcwbench | load generator + upstream, `GOMAXPROCS=2`, ghim CPU 2-3 |
| Tải | 32 client keep-alive vòng kín, khởi động 3 s, đo 20 s mỗi kịch bản; tổng thời gian chạy 3 phút 48 giây |
| Ghi chú | Máy dùng chung với các phiên khác (loadavg 3,5–5,8 trong lúc đo), nên req/s và độ trễ dao động. **CPU µs/req** ổn định (lệch ≤ 5 % giữa hai lần chạy) và là chỉ số chính của báo cáo này. |

## Kết quả

Lần chạy 2 (`go run ./cmd/hcwbench -waf /tmp/hcwwaf`). Cột cuối là CPU µs/req của lần
chạy 1 để thấy độ lặp lại.

| # | Kịch bản | req/s | p50 ms | p90 ms | p99 ms | max ms | Lỗi % | CPU engine (lõi) | CPU µs/req | RSS MB (nghỉ → cuối, đỉnh) | Kết nối upstream mới | Apply (POST) | CPU µs/req lần 1 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---|---:|
| 1 | Upstream trực tiếp (không WAF) | 39394 | 0.73 | 1.28 | 2.90 | 39.59 | 0.00 | – | – | – | 32 | – | – |
| 2 | mode off (proxy thuần) | 12714 | 2.21 | 4.47 | 7.67 | 23.48 | 0.00 | 1.55 | 122 | 19 → 26, 27 | 36 | 2 ms | 118 |
| 3 | block PL1, GET có query | 603 | 49.31 | 82.78 | 129.74 | 205.86 | 0.00 | 1.87 | 3092 | 58 → 95, 95 | 31 | 139 ms | 3085 |
| 4 | block PL1, POST JSON 2 KB | 47 | 679.71 | 877.93 | 1044.41 | 1203.89 | 0.00 | 1.95 | 41162 | 73 → 437, 437 | 26 | 172 ms | 41900 |
| 5 | block PL2, GET có query | 352 | 86.85 | 137.25 | 192.50 | 295.90 | 0.00 | 1.80 | 5107 | 58 → 96, 99 | 32 | 143 ms | 4928 |
| 6 | block PL1, tấn công SQLi (403) | 500 | 54.93 | 117.66 | 208.94 | 370.45 | 0.00 | 1.27 | 2550 | 59 → 86, 86 | 0 | 160 ms | 2439 |
| 7 | block PL1 + dynamic html, trang 50 KB (51 200 B → 69 097 B) | 638 | 48.37 | 78.67 | 118.51 | 209.25 | 0.00 | 1.86 | 2915 | 63 → 103, 109 | 36 | 182 ms | 2975 |
| 7a | block PL1, trang 50 KB (đối chứng của 7) | 962 | 30.14 | 56.67 | 87.85 | 127.30 | 0.00 | 1.96 | 2034 | 56 → 89, 89 | 32 | 136 ms | 2015 |
| 8 | block PL1, 200 site (định tuyến) | 607 | 49.82 | 81.68 | 112.47 | 178.41 | 0.00 | 1.95 | 3219 | 68 → 102, 103 | 199 | 200 site: đầu 151 ms, trung vị 3 ms, cuối 5 ms, tổng 0,7 s | 3346 |

Cách đọc:

- **CPU engine (lõi)** = giây CPU của tiến trình `hcw-waf` (utime+stime, `/proc/<pid>/stat`)
  trên mỗi giây đo. Giá trị gần 2,0 nghĩa là engine bão hoà 2 lõi được cấp. Kịch bản 6 ở
  lần 2 chỉ đạt 1,27 lõi (bị tiến trình khác tranh CPU), nên req/s của nó thấp hơn thực tế;
  ở lần 1 kịch bản này đạt 783 req/s với 1,91 lõi.
- Với 32 client mà engine đã bão hoà CPU, p50 ≈ 32 ÷ req/s chủ yếu là **thời gian xếp hàng**.
  Thời gian xử lý thực của một request xấp xỉ cột CPU µs/req.
- Kịch bản 1 bị giới hạn bởi chính hcwbench (load generator + upstream dùng 1,84/2 lõi),
  không phải bởi upstream.
- Tất cả kịch bản đều 0 % lỗi. Kịch bản 6 trả đúng 403 cho mọi request (0 kết nối upstream:
  không request tấn công nào lọt tới upstream).

Chỉ số suy ra (theo CPU µs/req, trên mỗi lõi):

| Cấu hình | CPU/request | Trần lý thuyết mỗi lõi | So với `off` |
|---|---:|---:|---:|
| off | 0,12 ms | ~8 300 req/s | 1× |
| PL1 GET (3) | 3,09 ms | ~325 req/s | 26× |
| PL1 tấn công (6) | 2,4–2,55 ms | ~400 req/s | 21× |
| PL2 GET (5) | 4,9–5,1 ms | ~200 req/s | 41× |
| PL1 POST JSON 2 KB (4) | 41–42 ms | ~24 req/s | 345× |
| PL1 + dynamic 50 KB (7) | 2,9–3,0 ms | ~340 req/s | 24× |

**Apply**: lần POST đầu tiên của một site có WAF mất 128–240 ms vì phải biên dịch CRS
(site `off`: 1–2 ms). Tạo lần lượt 200 site: trung vị 3 ms, site thứ 200 mất 5 ms, tổng
0,7–1,3 s. Mỗi POST áp lại toàn bộ cấu hình nên chi phí tăng tuyến tính theo số site
(~25 µs/site), vẫn nhỏ ở 200 site. Bộ CRS đã biên dịch tốn khoảng 40 MB RSS (site `off`
nghỉ ở 19 MB, site PL1 nghỉ ở 56–63 MB).

## Phân tích kịch bản nóng nhất (3: PL1, GET có query)

Engine không có endpoint pprof và máy không có `perf`, nên chi phí được phân rã bằng
**thí nghiệm loại trừ** chạy trên chính file nhị phân thật (mỗi dòng là một lần chạy
`-only 3 -d 5s`, CPU µs/req).

### Theo nhóm rule CRS (tắt bằng `disabled_rules` qua `-site-extra`)

| Nhóm rule bị tắt | Số rule | CPU µs/req | Giảm |
|---|---:|---:|---:|
| (không tắt) | 0 | 3021 | – |
| 913 scanner | 9 | 3108 | ~0 |
| 920 protocol enforcement | 68 | 2962 | 2 % |
| 921 protocol attack | 26 | 2899 | 4 % |
| 930+931 LFI/RFI | 27 | 2906 | 4 % |
| 932 RCE | 55 | 2505 | 17 % |
| 933 PHP | 29 | 2949 | 2 % |
| 934 generic | 19 | 2935 | 3 % |
| 941 XSS | 42 | 2575 | 15 % |
| 942 SQLi | 68 | 2747 | 9 % |
| 943+944 session/Java | 33 | 2707 | 10 % |
| 10 rule có regex lớn nhất (932235, 932370, 932250, 932230, 933120, 932380, 932260, 941160, 932340, 942151; 2,4–9 KB mỗi regex) | 10 | 2478 | 18 % |
| **Tất cả rule phát hiện 913–944** | 382 | **320** | **89 %** |
| Thêm cả 905/911/999 | 393 | 295 | 90 % |

Kết luận: chi phí **trải đều** trên hàng trăm rule. Không nhóm nào chiếm quá 17 %, các
regex khổng lồ chỉ khoảng 18 %. Tổng phần giảm khi tắt từng nhóm (~2 000 µs) nhỏ hơn phần
giảm khi tắt tất cả (~2 700 µs) vì các chuỗi transformation (`t:urlDecodeUni`,
`t:htmlEntityDecode`, `t:lowercase`…) được cache dùng chung giữa các rule. Không có "một
rule hỏng" nào để sửa: cách hiệu quả là **bớt chạy rule** cho request không cần.

### Theo hình dạng request (`-minimal-headers`, so 3 với 7a)

| Request | CPU µs/req |
|---|---:|
| GET không query, chỉ `User-Agent` + `Accept` (7a, `-minimal-headers`) | 891 |
| GET không query, header trình duyệt + 3 cookie (7a) | 2015–2034 |
| GET 5 tham số query, header tối thiểu (3, `-minimal-headers`) | 2133 |
| GET 5 tham số query, header trình duyệt + 3 cookie (3) | 3085–3092 |

- Phần cố định của một transaction Coraza+CRS (request gần như rỗng): ~0,7–0,8 ms trên mức proxy.
- Mỗi tham số query: ~250 µs (CRS kiểm tra cả `ARGS` và `ARGS_NAMES`).
- Header trình duyệt và 3 cookie: ~1,0–1,1 ms (cookie bị kiểm tra như tham số: `REQUEST_COOKIES` và `REQUEST_COOKIES_NAMES`).

### Body nhiều trường (kịch bản 4 và thử từng request)

Thời gian của một request POST JSON khi engine rảnh (curl, upstream tắt, nên kết quả là 502
sau khi kiểm tra xong):

| Số khoá JSON | Kích thước | Thời gian |
|---:|---:|---:|
| 10 | 191 B | 4–5 ms |
| 100 | 2 KB | 30–49 ms |
| 300 | 6,7 KB | 97–137 ms |
| 1 000 | 22,8 KB | 405–448 ms |

Chi phí tuyến tính ~0,4 ms/khoá. Engine không đặt `tx.max_num_args`, còn
`SecArgumentsLimit` của Coraza mặc định là 1 000, nên **chỉ cần ~2,5 request/giây loại
22 KB đã chiếm trọn một lõi**. Đây là kiểu khuếch đại tài nguyên dùng được cho DoS.

### Bộ nhớ và GC (`GODEBUG=gctrace=1`)

- Kịch bản 3: GC chiếm ~5 % CPU, heap sống 31–33 MB, cấp phát khoảng 340 KB/request.
- Kịch bản 4: heap sống **~200 MB** khi có 32 request đang được kiểm tra, tức khoảng
  **5 MB cho mỗi transaction đang mở**. Cấp phát ~3 MB/request, GC chiếm 4–6 % CPU.
  RSS 430–437 MB đến từ số transaction đang mở cùng lúc, không phải từ GC chậm.

## Ba cơ hội tối ưu hàng đầu

Cả ba đã được triển khai, số đo xem [Sau tối ưu](#sau-tối-ưu-giới-hạn-kiểm-tra-đường-tắt-file-tĩnh-bộ-mã-hoá-dynamic).

### 1. Giới hạn chi phí kiểm tra mỗi request và số transaction Coraza chạy đồng thời

**Bằng chứng**: kịch bản 4 tốn 41–42 ms CPU/request, RSS 437 MB. Chi phí tuyến tính
~0,4 ms/khoá (1 000 khoá = 0,41 s). Heap sống ~5 MB cho mỗi transaction đang mở. Trong
`serveSite`, transaction chỉ được `ProcessLogging()`/`Close()` qua `defer`, tức **sau khi
proxy xong toàn bộ phản hồi**. Với upstream chậm, SSE hay long polling (`FlushInterval: -1`),
mỗi kết nối giữ vài MB suốt thời gian stream.

**Đề xuất**:
- `wafpool.go` `directives()`: đặt `SecArgumentsLimit` và
  `setvar:tx.max_num_args=255` (rule 920380 của CRS sẽ chặn khi vượt), cân nhắc thêm
  `tx.arg_length`/`tx.total_arg_length`; cho phép chỉnh theo site.
- `engine.go` `serveSite`: thêm semaphore (kích thước ≈ 2×`GOMAXPROCS`, có timeout → 503)
  bao quanh đoạn `NewTransaction` → `inspect`.
- Gọi `ProcessLogging()` + `Close()` ngay sau `inspect`/`matched`, trước
  `up.proxy.ServeHTTP` (engine không xử lý phase phản hồi nên làm vậy an toàn).

**Ước tính**: chi phí xấu nhất mỗi request giảm từ ~0,41 s xuống ~0,1 s (−75 %). Với 4
transaction đồng thời thay vì 32, heap sống giảm từ ~200 MB xuống ~50 MB, RSS kịch bản 4 từ
~435 MB xuống ~120–150 MB (−65–70 %). Thông lượng không giảm vì engine đã dùng 1,95/2 lõi.

### 2. Đường tắt cho tài nguyên tĩnh (bớt chạy CRS ở nơi không có payload)

**Bằng chứng**: ngay cả GET không query đã tốn 0,9–2,0 ms CPU tuỳ header (so với 0,12 ms
khi `off`). Chi phí trải đều trên các rule (không nhóm nào > 17 %, regex lớn nhất chỉ
18 %), nên sửa một vài rule không giải quyết được.

**Đề xuất**: thêm tuỳ chọn site (ví dụ `static_fast_path`). Khi bật, request
`GET`/`HEAD` không query, không body, có phần mở rộng tĩnh (`.css .js .mjs .png .jpg .jpeg
.gif .svg .webp .avif .ico .woff .woff2 .ttf .map`) sẽ bỏ qua CRS. Bản thận trọng hơn chỉ
chạy một WAF rút gọn gồm rule phase 1 (920/921/913); bản này là một khoá khác trong
`WAFPool`. Hiện đã có `skip_waf` theo đường dẫn, nhưng phải cấu hình tay từng site.

**Ước tính**: request tĩnh giảm từ ~2,0 ms xuống 0,12–0,3 ms (−85–94 %). Một lượt xem
trang gồm 1 HTML và 20 tài nguyên tĩnh: CPU engine từ ~43 ms xuống ~9 ms (khoảng −80 %).
Phương án phụ cần đo trước khi làm: thay các operator `@rx/@pm/@detectSQLi/@detectXSS`
bằng bản RE2 (`coraza-wasilibs`). Theo thí nghiệm loại trừ, phần do regex lớn chỉ khoảng
18 %, nên kỳ vọng mức cải thiện vừa phải.

### 3. Viết lại đường mã hoá của dynamic protection

**Bằng chứng**: 7 so với 7a tốn thêm **0,88–0,96 ms CPU/request (+44–48 %)** và phản hồi
lớn thêm 35 % (51 200 → ~69 100 byte). `applyDynamic`/`protectHTML` sao chép payload
khoảng 6 lần:
`io.ReadAll` (cấp phát tăng dần) → slice XOR mới → `base64.EncodeToString` →
`json.Marshal` (thừa, vì bảng ký tự base64 không cần escape JSON) → nối chuỗi trong
`decoderJS` → `bytes.Buffer` không `Grow`. Ngoài ra có 5 lần gọi `crypto/rand` cho
`ident()`. Benchmark nháp với cùng chuỗi thao tác trên 50 KB (`GOMAXPROCS=1`) cho
**272–281 µs, 760 KB, 40 lần cấp phát/phản hồi**. Bản dùng một buffer cấp đúng kích thước
chỉ tốn **98–102 µs, 139 KB, 3 lần cấp phát**.

**Đề xuất**: đọc body vào buffer đúng `Content-Length` (lấy từ `sync.Pool`), XOR tại chỗ,
`base64.StdEncoding.Encode` thẳng vào buffer đầu ra đã cấp đủ, bỏ `json.Marshal`, tạo mọi
định danh từ một lần đọc `crypto/rand`.

**Ước tính**: giảm trực tiếp ~175 µs và −80 % cấp phát, nên phần chi phí thêm của dynamic
giảm từ ~0,9 ms xuống ~0,45–0,55 ms (−40–50 %), và req/s của kịch bản 7 tăng ~15–20 %.

## Quan sát khác (ưu tiên thấp hơn)

- **Mỗi site một `http.Transport`**: 200 site cùng một upstream mở 199 kết nối, trong khi
  1 site chỉ cần ~31. Mỗi pool giữ tối đa 128 kết nối rảnh, nên N site có thể giữ tới 128×N.
  Ngoài ra, mỗi lần `Apply` tạo transport mới và `CloseIdleConnections()` transport cũ, tức
  mọi thay đổi cấu hình đều cắt toàn bộ keep-alive tới upstream. Nên dùng chung transport
  theo (scheme, host, `upstream_insecure`). CPU/request của kịch bản 8 chỉ cao hơn kịch bản
  3 khoảng 4–8 % (gần mức nhiễu), nên chi phí định tuyến map/wildcard không đáng kể.
- **PL2 đắt hơn PL1 60–65 %** (4,9–5,1 ms so với 3,1 ms): nên ghi rõ trong tài liệu khi
  khuyến nghị PL2.
- **Request tấn công không rẻ hơn** request lành bao nhiêu (2,4–2,55 ms, −20 %), vì CRS
  chạy theo chế độ cộng điểm và chỉ chặn ở cuối phase 2. Lũ request tấn công vì vậy cần
  được chặn sớm bằng rate limit/ACL, và hai lớp này đã đứng trước WAF trong `serveSite`.
- Mỗi biến thể WAF (khác mode/paranoia/threshold/disabled_rules/custom_rules) là một lần
  biên dịch CRS (128–240 ms) và khoảng +40 MB RSS. Site có `disabled_rules` riêng sẽ
  nhân bộ nhớ (mới đo một biến thể).
- `events.CountRequest` khoá một mutex toàn cục và gọi `time.Now()` ở mọi request. Ở mức
  ≤ 13 000 req/s đo được thì chưa thành vấn đề.

## Sau tối ưu (giới hạn kiểm tra, đường tắt file tĩnh, bộ mã hoá dynamic)

Thay đổi trong engine (chi tiết: [docs/engine.vi.md](../docs/engine.vi.md#giới-hạn-kiểm-tra)):

- `SecArgumentsLimit` + CRS `tx.max_num_args` = 255 (site `max_args`); vượt quá trả 400
  bằng rule 100002/100003 **trước** khi rule CRS nào của phase đó chạy. JSON sâu tối đa 64.
- Body được phân tích thành tham số (JSON, form, XML) lớn hơn `body_args_limit_kb`
  (mặc định 128 KB) trả 413 ở site `block`.
- Tối đa `waf_concurrency` (mặc định 2 × `GOMAXPROCS`) lượt kiểm tra CRS chạy cùng lúc;
  body được đọc trước khi chiếm lượt; transaction Coraza đóng ngay khi có kết quả,
  trước khi proxy.
- Tuỳ chọn site `static_fast_path` (mặc định tắt).
- Dynamic protection: một buffer cấp đúng kích thước, bỏ `json.Marshal`, một lần đọc
  `crypto/rand`, buffer đọc body lấy từ `sync.Pool`.

### Đo lại

Cùng máy ảo 4 vCPU nhưng **là một phiên máy khác** với bảng trên (sau khi khởi động lại,
mọi kịch bản CRS chậm hơn ~15 %), nên chỉ so các lần chạy trong cùng phiên. Thứ tự chạy:
sau (1) → trước → sau (2), mỗi kịch bản 20 s, 32 client. Bản "trước" là commit `9061297`.

| # | Kịch bản | CPU µs/req trước | CPU µs/req sau (1 / 2) | RSS đỉnh MB trước → sau | req/s trước → sau |
|---|---|---:|---:|---|---|
| 2 | mode off | 141 | 145 / 143 | 26 → 28 | 11 360 → 10 963–11 159 |
| 3 | PL1, GET có query | 3 767 | 4 202 / 4 215 | 92 → 81–82 | 513 → 469–472 |
| 4 | PL1, POST JSON 2 KB (~100 trường) | 58 180 | 60 320 / 54 381 | **421 → 121–124** | 34 → 33–36 |
| 4b | PL1, POST JSON 1 000 khoá (~28 KB) | **1 193 636** (200) | **1 167 / 1 153** (400) | **2 344 → 85** | 2 → 1 664–1 711 |
| 6 | PL1, tấn công SQLi (403) | 3 129 | 3 290 / 3 310 | 81 → 81 | 631 → 598–603 |
| 7 | PL1 + dynamic html, 50 KB | 3 401 | 2 964 / 2 606 | 99 → 83 | 577 → 622–755 |
| 7a | PL1, 50 KB (đối chứng của 7) | 2 392 | 2 369 / 2 733 | 87 → 81 | 824 → 723–833 |
| 9 | PL1, file tĩnh `.css` | 2 386 | 2 576 / 2 536 | 87 → 81 | 825 → 771–775 |
| 9a | như 9 + `static_fast_path` | – | **647 / 637** | – → 80–81 | – → 3 043–3 067 |

Đọc bảng:

- **4b (DoS nhiều khoá)**: bản cũ tốn **1,19 giây CPU** và giữ 2,3 GB RSS cho mỗi request
  28 KB. Bản mới dừng phân tích ở khoá thứ 256 và trả 400 trước khi CRS chạy:
  **1,2 ms** (≈ 1 000 lần rẻ hơn), RSS 85 MB. Không còn khuếch đại tài nguyên theo số khoá.
- **4 (RSS)**: chi phí CPU không đổi (request hợp lệ vẫn được kiểm tra đầy đủ), nhưng chỉ
  4 transaction mở cùng lúc thay vì 32 và transaction đóng trước khi proxy, nên RSS đỉnh
  giảm **71 %** (421 → 121 MB). Thông lượng không giảm vì CPU vẫn bão hoà (1,95–1,98 lõi).
- **9a (file tĩnh)**: 2,4–2,6 ms → **0,64 ms CPU/request (−74 %)**, req/s ×3,9.
- **7 (dynamic)**: phần chi phí thêm so với 7a giảm từ ~1,0 ms xuống ~0,0–0,6 ms (nhiễu của
  hai kịch bản lớn hơn hiệu số). Số đo ổn định hơn từ benchmark Go trên 50 KB
  (`BenchmarkApplyDynamicHTML50K`, `-cpu 1`): **382–407 µs, 631 KB, 70 lần cấp phát →
  109–115 µs, 74 KB, 14 lần cấp phát** mỗi response. Kết quả khớp từng byte với bộ mã hoá
  cũ (`TestDynamicEncoderMatchesPrevious`).
- **3, 6, 7a, 9**: chênh lệch nằm trong mức nhiễu của máy dùng chung. Chạy xen kẽ
  `-only 3,9 -d 12s` hai vòng: kịch bản 3 trước 4 477 / 4 168 µs, sau 4 155 / 4 023 µs;
  kịch bản 9 trước 2 685 / 2 769 µs, sau 2 716 / 2 681 µs. Benchmark Go của riêng phần
  `inspect` (cùng request kịch bản 3, cấu hình SecLang cũ và mới) cũng cho cùng mức
  3,4–4,0 ms. Các giới hạn mới không làm request thường đắt hơn.

### Phát hiện thêm: chi phí theo byte

Giới hạn số khoá chưa đủ: CRS còn tốn CPU theo **độ dài giá trị**, khoảng 6–8 µs/byte ở
PL1. Đo trên engine cũ (một request, máy rảnh): body JSON một trường 300 KB tốn 1,8 s,
form một trường 128 KB tốn 1,0 s; body 1 MB (`body_limit_kb` mặc định) tốn ~8 s. Vì vậy
engine thêm `body_args_limit_kb` (mặc định 128 KB, như `SecRequestBodyNoFilesLimit` của
ModSecurity): body JSON/form/XML lớn hơn bị trả 413 ngay từ `Content-Length` (hoặc sau
khi đọc 128 KB nếu gửi chunked), nên trường hợp xấu nhất mỗi request còn ~1 s CPU thay
vì ~8 s, và với `waf_concurrency` số request như vậy chạy cùng lúc bị giới hạn. Body
multipart chưa có giới hạn riêng (phần text của multipart vẫn tính theo `body_limit_kb`).

### Tái lập phần sau tối ưu

```sh
cd waf && go build -o /tmp/hcwwaf ./cmd/hcw-waf && cd ../bench
go run ./cmd/hcwbench -waf /tmp/hcwwaf -only 2,3,4,4b,6,7,7a,9,9a
cd ../waf && go test ./internal/proxy -run XXX -bench ApplyDynamicHTML50K -benchtime 2000x -cpu 1
```

## Tái lập

```sh
cd waf && go build -o /tmp/hcwwaf ./cmd/hcw-waf && cd ../bench
go run ./cmd/hcwbench -waf /tmp/hcwwaf -json /tmp/hcwbench.json         # bảng chính (~4 phút)
go run ./cmd/hcwbench -only 3,7a -minimal-headers -d 5s -warmup 1s       # ảnh hưởng của header/cookie
go run ./cmd/hcwbench -only 3 -d 5s -site-extra '{"disabled_rules":[932235,932370,932250,932230,933120,932380,932260,941160,932340,942151]}'
GODEBUG=gctrace=1 go run ./cmd/hcwbench -only 4 -d 6s -keep               # xem GC trong engine.log
```

Danh sách ID của từng nhóm rule (để tắt cả nhóm) lấy từ các file
`REQUEST-9xx-*.conf` của module `github.com/corazawaf/coraza-coreruleset/v4@v4.25.0`.
