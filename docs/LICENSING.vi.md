# Giấy phép & phạm vi sử dụng

> Tài liệu kỹ thuật, không phải tư vấn pháp lý. Trước khi thương mại hóa, hãy
> nhờ luật sư sở hữu trí tuệ rà soát.

## 1. Phần mã nguồn trong repo này — GPL-3.0

Repo được tạo từ <https://github.com/chaitin/safeline> (commit `7dee6104`).
Toàn bộ mã nguồn có trong đó (`management/`, `mcp_server/`, `sdk/`, `yanshi/`,
`scripts/`) dùng giấy phép **GPL-3.0**. HiTechCloud được phép:

- sửa đổi, đổi thương hiệu (whitelabel) và bán hoặc cung cấp dịch vụ;
- với điều kiện giữ `LICENSE.md`, ghi nguồn gốc (`NOTICE.md`), và **cung cấp
  mã nguồn** phần đã sửa cho người nhận khi phân phối bản build.

Module mới `cluster/` do HiTechCloud viết, cũng phát hành theo GPL-3.0.

## 2. Docker image `chaitin/safeline-*` — KHÔNG thuộc GPL

Lõi WAF thực tế (detector/engine phân tích ngữ nghĩa, tengine, luigi, fvm,
chaos và console v9 trong `mgt`) **không có mã nguồn trong repo**. Chaitin chỉ
phát hành chúng dưới dạng image đã build sẵn, kèm một EULA riêng hiển thị trong
console. Chủ sở hữu bản quyền được phép cấp phép kép, nên việc repo dùng GPL
không làm EULA của các image mất hiệu lực. Trong EULA đó có các điều khoản:

- chỉ cấp phép cài đặt trên **một thiết bị**; không được chuyển nhượng hay cấp phép lại;
- cấm đóng gói lại, sửa đổi, tạo sản phẩm phái sinh;
- cấm cho thuê, bán hoặc phân phối;
- cấm sửa hay xóa thông báo bản quyền và thương hiệu;
- cấm dùng làm năng lực chính để cung cấp **dịch vụ cloud hoặc mạng thương mại**.

Vì vậy, các phần sau **phải có văn bản cho phép riêng của Chaitin** bao quát
đúng từng hành vi:

| Hành vi | Cần cho phép? |
|---|---|
| Chạy image gốc trên nhiều node (cluster) | Có (EULA: một thiết bị) |
| Cung cấp WAF như dịch vụ cho khách hàng của HiTechCloud | Có |
| Build image console đã whitelabel (`branding/console`) | Có |
| Phân phối image đã sửa cho khách hàng | Có |
| Sửa lõi detector/tengine | Có, **và** cần Chaitin cung cấp mã nguồn |

Khuyến nghị:

- Lưu văn bản cho phép (hợp đồng OEM/whitelabel) trong hồ sơ pháp chế.
- Chỉ đẩy image đã sửa lên registry riêng.
- Không sửa nội dung EULA hay thông báo bản quyền bên trong image.

## 3. Nếu cần độc lập hoàn toàn

Nếu không có thỏa thuận OEM, có thể thay lớp engine bằng một engine mã nguồn
mở, ví dụ OWASP Coraza (Apache-2.0) + Core Rule Set, hoặc ModSecurity. Module
`cluster/` không phụ thuộc vào engine: chỉ cần engine có HTTP API quản trị, hoặc
viết thêm adapter.
