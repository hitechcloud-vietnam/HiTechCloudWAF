# 02 – Tối ưu hiệu năng engine (theo `bench/RESULTS.md`)

**Trạng thái:** đang làm dở (nhánh `worktree-agent-a0e14b48f2332c148` trong
máy phát triển, chưa merge). Nếu nhánh đó không còn, làm lại từ đầu theo
mô tả dưới.
**Ưu tiên:** cao (bảo vệ chống DoS bằng body JSON nhiều khoá).
**Code:** `waf/internal/proxy/{wafpool.go,engine.go,dynamic.go}`, `waf/internal/model`.

## Việc cần làm
1. Giới hạn số tham số (`SecArgumentsLimit`, `tx.max_num_args`, ví dụ 255) –
   CRS 920380 chặn khi vượt.
2. Semaphore ~2×GOMAXPROCS bao quanh tạo transaction Coraza + `inspect`; client
   bỏ đi thì trả 503.
3. Gọi `ProcessLogging()`/`Close()` ngay sau `inspect` (không `defer` tới hết
   response) – giải phóng ~5 MB/transaction với SSE/long-poll. Giữ nguyên
   việc thu thập rule khớp cho sự kiện.
4. Tuỳ chọn site `static_fast_path` (mặc định tắt): GET/HEAD không query, không
   body, đuôi tĩnh → bỏ CRS phase 2. Không bao giờ bỏ ACL/rate limit/challenge.
5. Viết lại bộ mã hoá dynamic protection: một buffer cấp đúng kích thước, bỏ
   `json.Marshal` thừa, output tương thích byte-by-byte (test Node trong
   `dynamic_test.go` phải qua).
6. Đo lại bằng `bench/cmd/hcwbench`, cập nhật `bench/RESULTS.md` (chỉ số tin
   cậy: CPU µs/req).

## Hoàn thành khi
`cd waf && go test -race ./...` xanh, `HCW_E2E=1 go test ./...` trong `e2e/`
xanh, RESULTS.md có số liệu trước/sau, CHANGELOG ghi lại.
