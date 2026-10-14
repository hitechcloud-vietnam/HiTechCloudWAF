# 07 – Bản tiếng Anh của tài liệu mới

**Trạng thái:** gần xong (còn bản dịch hướng dẫn triển khai, do người khác
làm). **Ưu tiên:** thấp.

## Đã xong

- `docs/en/engine.md`, `docs/en/cluster.md`, `docs/en/install.md` khớp bản
  tiếng Việt hiện tại (cùng mục, cùng thứ tự, cùng lệnh/cấu hình): cache, gzip,
  cân bằng tải + sticky + sửa header, threat intelligence, bot đã xác minh,
  giới hạn kiểm tra + `static_fast_path`, trang Sự kiện + API sự kiện, GeoDNS,
  bản ghi DNS tĩnh, đăng ký node, ghi chú bảo mật.
- Thêm `docs/en/kubernetes.md` (dịch từ `docs/kubernetes.vi.md`).
- Dòng chuyển ngôn ngữ ở đầu engine, cluster, install, kubernetes (cả hai
  chiều).

## Còn lại

- `docs/deploy.vi.md` → `docs/en/deploy.md` (dịch sát, giữ lệnh) – **đang có
  người khác làm**, kèm dòng chuyển ngôn ngữ ở đầu `deploy.vi.md`. Khi xong,
  đổi liên kết `../deploy.vi.md` trong `docs/en/install.md` sang `deploy.md`.
- `README.en.md` (cùng người phụ trách): thêm liên kết tới
  `docs/en/kubernetes.md` (hiện README tiếng Việt đã trỏ tới
  `docs/kubernetes.vi.md`).
- Dashboard controller (`cluster/internal/controller/dashboard.html`) chỉ có
  tiếng Việt, nên bản tiếng Anh ghi nhãn tiếng Việt kèm chú thích (*Đăng ký
  node*, *Đổi secret*, *Xác thực*, *Bản ghi DNS tĩnh*). Khi dashboard có bản
  dịch, cập nhật lại các nhãn này.
- Quy ước: mỗi lần sửa `docs/*.vi.md` thì sửa luôn bản trong `docs/en/` trong
  cùng commit.
