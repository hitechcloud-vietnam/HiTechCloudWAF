# hcwctl — công cụ dòng lệnh quản trị HiTechCloud WAF

`hcwctl` gọi API quản trị của một node HiTechCloud WAF (mặc định cổng `9443`,
xem bảng API trong [docs/engine.vi.md](../docs/engine.vi.md)) để quản lý site,
chứng chỉ, người dùng, xem sự kiện tấn công, thống kê, nhật ký kiểm toán, sao
lưu và khôi phục cấu hình. Công cụ chỉ dùng thư viện chuẩn của Go.

## Cài đặt

```sh
cd ctl
go build -o hcwctl ./cmd/hcwctl
# gắn số phiên bản:
go build -ldflags "-X github.com/hitechcloud-vietnam/HiTechCloudWAF/ctl/internal/cli.Version=v0.1.0" -o hcwctl ./cmd/hcwctl
sudo install -m 0755 hcwctl /usr/local/bin/
```

## Đăng nhập và profile

`hcwctl login` kiểm tra thông tin đăng nhập (gọi `GET /api/open/me`) rồi lưu
profile vào `~/.config/hcwctl/config.json` (quyền `0600`, thư mục `0700`).
Profile chứa **một** trong hai loại thông tin xác thực:

- **API token** của node (gửi qua header `X-HCW-API-TOKEN`), quyền admin;
- **phiên đăng nhập** của tài khoản console (header `X-HCW-Session`), theo vai
  trò `admin` hoặc `viewer` (chỉ đọc).

```sh
# Bằng API token đọc từ file (an toàn hơn truyền trên dòng lệnh)
hcwctl login --url https://waf.example.com:9443 --token-file /etc/hcw-waf/api.token

# Bằng tài khoản console: mật khẩu lấy từ $HCWCTL_PASSWORD hoặc nhập từ stdin
# (không hiện ký tự khi nhập từ terminal); nếu tài khoản bật 2FA, hcwctl hỏi
# thêm mã OTP (hoặc dùng --otp / $HCWCTL_OTP).
hcwctl login --url https://waf.example.com:9443 --user admin

# Nhiều node: mỗi node một profile; lần login cuối là profile hiện hành
hcwctl login --profile hn  --url https://waf-hn.example.com:9443  --token-file hn.token
hcwctl login --profile hcm --url https://waf-hcm.example.com:9443 --token-file hcm.token
hcwctl profiles                 # liệt kê (không bao giờ in token)
hcwctl profiles use hn          # đổi profile hiện hành
hcwctl --profile hcm sites list # dùng profile khác cho một lệnh
hcwctl logout --profile hcm     # xoá profile (và kết thúc phiên trên server)
```

Biến môi trường:

| Biến | Ý nghĩa |
|---|---|
| `HCWCTL_URL`, `HCWCTL_TOKEN`, `HCWCTL_CA` | ghi đè URL / token / file CA của profile (dùng được cả khi chưa có file cấu hình) |
| `HCWCTL_PROFILE` | profile mặc định thay cho profile hiện hành |
| `HCWCTL_CONFIG` | đường dẫn file cấu hình khác |
| `HCWCTL_PASSWORD`, `HCWCTL_OTP` | mật khẩu và mã OTP cho `login --user` |
| `HCWCTL_NEW_PASSWORD` | mật khẩu cho `users add` (không hỏi từ stdin) |

### TLS

- Chứng chỉ của API **luôn được kiểm tra** theo kho CA của hệ thống.
- `--ca FILE` ghim (pin) một CA hoặc chính chứng chỉ của node: chỉ file đó được
  tin cậy. Node tự sinh chứng chỉ tự ký lưu ở `data_dir/api.crt`, ví dụ:
  `hcwctl login --url https://10.0.0.5:9443 --ca ./api.crt --token-file api.token`.
- `--insecure` (bỏ kiểm tra chứng chỉ) **chỉ được phép với địa chỉ loopback**
  (`127.0.0.1`, `::1`, `localhost`); với host khác hcwctl từ chối và gợi ý dùng
  `--ca`. Quy tắc này được kiểm tra lại mỗi lần chạy, kể cả khi `HCWCTL_URL`
  trỏ profile sang host khác.
- Chỉ hỗ trợ `https://`; hcwctl không theo redirect để không gửi token tới nơi khác.

## Định dạng đầu ra và mã thoát

Mặc định in bảng cho người đọc; `-o json` in JSON gốc của API (phần `data`),
tiện cho `jq`. Cờ chung `--profile` và `-o` đặt được trước hoặc sau lệnh.

Mã thoát: `0` thành công, `1` lỗi API hoặc dữ liệu không hợp lệ, `2` sai cú pháp
lệnh. Token, mật khẩu và khoá riêng không bao giờ được in ra (`certs list -o json`
thay khoá bằng `<redacted>`; chỉ `backup` xuất khoá riêng).

## Site

```sh
hcwctl sites list
hcwctl sites get 3
hcwctl sites get 3 -o json > site3.json

cat > shop.json <<'EOF'
{"name": "shop", "server_names": ["shop.example.com"], "ports": ["80", "443_ssl"],
 "upstreams": ["http://10.0.0.5:8080"], "cert_id": 1, "mode": "block"}
EOF
hcwctl sites create -f shop.json
cat shop.json | hcwctl sites create -f -

# update THAY TOÀN BỘ site: nên lấy JSON hiện tại, sửa rồi gửi lại
hcwctl sites get 3 -o json > s.json && vi s.json && hcwctl sites update -f s.json
hcwctl sites update 3 -f s.json      # ID trên dòng lệnh ghi đè trường "id"
hcwctl sites delete 3 4

# Thao tác nhanh (đọc site, đổi một trường, ghi lại; giữ nguyên các trường khác)
hcwctl sites set-mode 3 monitor              # block | monitor | off
hcwctl sites deny-ip 3 203.0.113.7 198.51.100.0/24
hcwctl sites disable-rule 3 942100           # tắt rule CRS bị báo nhầm
hcwctl sites allow-rule 3 942100             # bật lại (xoá khỏi disabled_rules)
```

## Chứng chỉ

```sh
hcwctl certs list                                   # ID, domain, issuer, ngày hết hạn
hcwctl certs add --crt fullchain.pem --key privkey.pem
hcwctl certs add --crt c.pem --key k.pem --domains shop.example.com,www.shop.example.com
hcwctl certs delete 2
```

## Sự kiện, thống kê, upstream, kiểm toán

```sh
hcwctl events                         # 50 sự kiện gần nhất, cũ trước mới sau
hcwctl events --site 3 --limit 200
hcwctl events --follow                # hỏi lại mỗi 2 giây, chỉ in sự kiện mới (Ctrl-C để dừng)
hcwctl events --follow -o json | jq . # mỗi dòng một sự kiện JSON (NDJSON)
hcwctl stats                          # bộ đếm theo site + tổng
hcwctl upstreams                      # tình trạng health check của upstream
hcwctl audit --limit 100              # nhật ký thao tác quản trị (admin)
```

## Người dùng console

```sh
hcwctl users list
hcwctl users add alice --role viewer        # hỏi mật khẩu (hoặc $HCWCTL_NEW_PASSWORD)
HCWCTL_NEW_PASSWORD='...' hcwctl users add bob --role admin
hcwctl users delete alice
```

## Sao lưu và khôi phục

```sh
hcwctl backup > backup.json                 # gồm cả khoá riêng: giữ file cẩn thận
hcwctl backup --file backup.json            # ghi file với quyền 0600
hcwctl restore backup.json                  # hỏi xác nhận, gõ "yes"
hcwctl restore --yes backup.json            # dùng trong script
cat backup.json | hcwctl restore --yes -
```

`restore` **thay toàn bộ** site và chứng chỉ trên node; cấu hình được kiểm tra
trước khi áp dụng, nếu lỗi node giữ nguyên cấu hình đang chạy. File lưu bằng
`curl` (có lớp `{"data": ...}`) cũng được chấp nhận.

## Khác

```sh
hcwctl alerts test        # gửi thông báo thử (Telegram/webhook trong waf.yaml)
hcwctl version            # phiên bản hcwctl và của node
hcwctl version --client   # không gọi server
hcwctl help
```

## Phát triển

```sh
cd ctl
gofmt -l . && go vet ./... && go test -race ./...
```

Các test dùng `httptest.NewTLSServer` giả lập API (kiểm tra method, đường dẫn,
header xác thực, body, đầu ra bảng/JSON, quyền file cấu hình, quy tắc
`--insecure` chỉ cho loopback).
