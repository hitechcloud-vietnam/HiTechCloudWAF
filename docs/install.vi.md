English: [en/install.md](en/install.md)

# Cài đặt HiTechCloud WAF

> Hướng dẫn đầy đủ từng bước (tường lửa, HTTPS, cluster, bảo mật, giám sát,
> sao lưu, nâng cấp, xử lý sự cố): [deploy.vi.md](deploy.vi.md).

Có hai cách cài: dùng **binary + systemd** (khuyên dùng, không cần Docker)
hoặc dùng **Docker** (`waf/deploy/compose.yaml`, image trên GHCR).

Binary và `install.sh` nằm ở trang Releases của repo. Workflow
`.github/workflows/release.yml` tự build khi gắn tag `v*`.

## 1. Một node WAF đơn lẻ

```bash
curl -fsSLO https://github.com/hitechcloud-vietnam/HiTechCloudWAF/releases/latest/download/install.sh
sudo bash install.sh node
```

Script sẽ:

- cài `/usr/local/bin/hcw-waf`;
- tạo user hệ thống `hcwwaf`;
- sinh API token ngẫu nhiên vào `/etc/hcw-waf/api.token`;
- ghi `/etc/hcw-waf/waf.yaml` và service `hcw-waf` (có hardening systemd,
  chỉ giữ quyền mở cổng 80/443).

Console mặc định chỉ nghe ở `127.0.0.1:9443`:

```bash
ssh -L 9443:127.0.0.1:9443 root@<server>   # rồi mở https://127.0.0.1:9443/
```

Nếu muốn mở console ra mạng nhưng chỉ cho một dải IP truy cập:
`sudo bash install.sh node --public-console 203.0.113.0/24`.

Repo private: truyền thêm token đọc được repo qua `sudo`, ví dụ
`sudo GITHUB_TOKEN=<token> bash install.sh node` (`sudo` mặc định không giữ
biến môi trường đặt trước nó).

## 2. Cluster nhiều node + DNS

```bash
# Máy quản trị (thường kiêm luôn node primary)
sudo bash install.sh node
sudo bash install.sh controller --name ctl.waf.example.vn --ip 203.0.113.5

# Mỗi node WAF (enroll.token: token dùng một lần tạo trên dashboard controller)
sudo bash install.sh node
sudo bash install.sh agent --controller https://ctl.waf.example.vn:7443 \
  --enroll-token-file enroll.token --ca ca.crt --region hn --pools web --ipv4 <IP public>

# Ít nhất 2 máy DNS
sudo bash install.sh dns --controller https://ctl.waf.example.vn:7443 \
  --dns-token-file dns.token --ca ca.crt --zone waf.example.vn \
  --ns ns1.waf.example.vn,ns2.waf.example.vn
```

- `ca.crt` lấy từ `/etc/hcw/tls/ca.crt`, `dns.token` từ
  `/etc/hcw/secrets/dns.token` trên máy controller.
- `enroll.token`: tạo trên dashboard controller (mục *Đăng ký node*) hoặc
  `POST /v1/enroll-tokens`, mỗi node một token, chỉ dùng được một lần (xem
  mục *Đăng ký node* trong [cluster.vi.md](cluster.vi.md)).
- Token dùng chung `--node-token-file node.token` (`/etc/hcw/secrets/node.token`)
  vẫn chạy nhưng đã lỗi thời. Các tuỳ chọn `--…-file` giữ token khỏi dòng
  lệnh và lịch sử shell.

**Cấu hình dùng chung giữa các node:**

- Tạo site và chứng chỉ trên console của node primary; agent tự đồng bộ sang
  mọi node.
- Đặt cùng `challenge_secret_file` trên mọi node để khách không phải giải lại
  anti-bot khi bị chuyển sang node khác.

**Phía tên miền:**

1. Ở nhà đăng ký, khai báo glue record cho `ns1`/`ns2`.
2. Trong `/etc/hcw/dns.yaml`, thêm record A cho các NS.
3. Khách hàng trỏ CNAME về `edge.waf.example.vn`.

## 3. Docker

```bash
cd waf/deploy && docker compose up -d   # engine + agent
```

Image: `ghcr.io/hitechcloud-vietnam/hitechcloud-waf` và
`ghcr.io/hitechcloud-vietnam/hitechcloud-waf-cluster`. CI đẩy image mỗi lần
merge vào `main`. Nếu package trên GHCR để private, chạy `docker login ghcr.io`
trước khi pull, hoặc đặt package ở chế độ public.

## Cập nhật

Chạy lại `install.sh <vai trò>` với `--version vX.Y.Z`, rồi khởi động lại
service (ví dụ):

```bash
sudo systemctl restart hcw-waf
```

Token đã có và `waf.yaml` được giữ nguyên. Riêng `controller.yaml`,
`agent.yaml` và `dns.yaml` được ghi lại từ template theo tham số của lệnh, nên
khi cập nhật vai trò `agent`/`dns` phải truyền lại đủ tham số như lúc cài; nếu
đã sửa tay các file này, hãy sao lưu trước khi cập nhật.

## Gỡ bỏ

```bash
sudo systemctl disable --now hcw-waf hcw-agent hcw-controller hcw-dns 2>/dev/null
sudo rm -rf /usr/local/bin/hcw-waf /usr/local/bin/hcw /etc/hcw-waf /etc/hcw \
  /var/lib/hcw-waf /var/lib/hcw /var/lib/hcw-dns /etc/systemd/system/hcw-*.service
```
