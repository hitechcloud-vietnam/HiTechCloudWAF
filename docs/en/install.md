Tiếng Việt: [install.vi.md](../install.vi.md)

# Installing HiTechCloud WAF

> The full step-by-step guide (firewall, HTTPS, cluster, security, monitoring,
> backups, upgrades, troubleshooting) is currently available in Vietnamese
> only: [deploy.vi.md](../deploy.vi.md).

There are two ways to install: **binary + systemd** (recommended, no Docker
needed) or **Docker** (`waf/deploy/compose.yaml`, images on GHCR).

The binaries and `install.sh` are on the repository's Releases page. The
`.github/workflows/release.yml` workflow builds them automatically when a
`v*` tag is pushed.

## 1. A single WAF node

```bash
curl -fsSLO https://github.com/hitechcloud-vietnam/HiTechCloudWAF/releases/latest/download/install.sh
sudo bash install.sh node
```

The script:

- installs `/usr/local/bin/hcw-waf`;
- creates the `hcwwaf` system user;
- generates a random API token in `/etc/hcw-waf/api.token`;
- writes `/etc/hcw-waf/waf.yaml` and the `hcw-waf` service (with systemd
  hardening; it only keeps the right to open ports 80/443).

By default the console only listens on `127.0.0.1:9443`:

```bash
ssh -L 9443:127.0.0.1:9443 root@<server>   # then open https://127.0.0.1:9443/
```

To expose the console on the network but allow only one IP range:
`sudo bash install.sh node --public-console 203.0.113.0/24`.

Private repository: pass a token that can read the repository through
`sudo`, for example `sudo GITHUB_TOKEN=<token> bash install.sh node` (by
default `sudo` does not keep environment variables set in front of it).

## 2. Multi-node cluster + DNS

```bash
# Admin machine (usually also the primary node)
sudo bash install.sh node
sudo bash install.sh controller --name ctl.waf.example.vn --ip 203.0.113.5

# Each WAF node (enroll.token: one-time token created on the controller dashboard)
sudo bash install.sh node
sudo bash install.sh agent --controller https://ctl.waf.example.vn:7443 \
  --enroll-token-file enroll.token --ca ca.crt --region hn --pools web --ipv4 <public IP>

# At least 2 DNS machines
sudo bash install.sh dns --controller https://ctl.waf.example.vn:7443 \
  --dns-token-file dns.token --ca ca.crt --zone waf.example.vn \
  --ns ns1.waf.example.vn,ns2.waf.example.vn
```

- `ca.crt` comes from `/etc/hcw/tls/ca.crt` and `dns.token` from
  `/etc/hcw/secrets/dns.token` on the controller machine.
- `enroll.token`: created on the controller dashboard (*Đăng ký node* – node
  enrollment section) or with `POST /v1/enroll-tokens`, one token per node,
  usable only once (see *Node enrollment* in [cluster.md](cluster.md)).
- The shared token `--node-token-file node.token`
  (`/etc/hcw/secrets/node.token`) still works but is deprecated. The
  `--…-file` options keep tokens out of the command line and shell history.

**Configuration shared between nodes:**

- Create sites and certificates on the primary node's console; the agents
  replicate them to every node automatically.
- Set the same `challenge_secret_file` on every node so visitors do not have
  to solve the anti-bot challenge again when they are moved to another node.

**Domain side:**

1. At the registrar, declare glue records for `ns1`/`ns2`.
2. In `/etc/hcw/dns.yaml`, add A records for the name servers.
3. Customers point a CNAME to `edge.waf.example.vn`.

## 3. Docker

```bash
cd waf/deploy && docker compose up -d   # engine + agent
```

Images: `ghcr.io/hitechcloud-vietnam/hitechcloud-waf` and
`ghcr.io/hitechcloud-vietnam/hitechcloud-waf-cluster`. CI pushes images on
every merge into `main`. If the GHCR packages are private, run
`docker login ghcr.io` before pulling, or make the packages public.

## Updating

Run `install.sh <role>` again with `--version vX.Y.Z`, then restart the
service (for example):

```bash
sudo systemctl restart hcw-waf
```

Existing tokens and `waf.yaml` are kept. `controller.yaml`, `agent.yaml` and
`dns.yaml`, however, are rewritten from the template using the command's
options, so when updating the `agent`/`dns` roles pass the same options as at
install time; if you edited these files by hand, back them up before
updating.

## Uninstalling

```bash
sudo systemctl disable --now hcw-waf hcw-agent hcw-controller hcw-dns 2>/dev/null
sudo rm -rf /usr/local/bin/hcw-waf /usr/local/bin/hcw /etc/hcw-waf /etc/hcw \
  /var/lib/hcw-waf /var/lib/hcw /var/lib/hcw-dns /etc/systemd/system/hcw-*.service
```
