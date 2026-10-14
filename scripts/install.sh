#!/usr/bin/env bash
# HiTechCloud WAF installer (systemd).
#
#   install.sh node        [--public-console CIDR] [--geoip] [--version vX.Y.Z]
#   install.sh agent       --controller https://ctl:7443 --node-token TOKEN --ca ca.crt [--region hn] [--pools web] [--ipv4 PUBLIC_IP]
#   install.sh controller  --name ctl.example.vn [--ip 203.0.113.5]
#   install.sh dns         --controller https://ctl:7443 --dns-token TOKEN --ca ca.crt --zone waf.example.vn --ns ns1.waf.example.vn,ns2.waf.example.vn
#
# Common options:
#   --version vX.Y.Z   release to install (default: latest)
#   --binary PATH      use a local binary instead of downloading
#   --no-start         write files only
#   --node-token-file F / --dns-token-file F  read the token from a file
#                      (keeps it out of the process list and shell history)
# Environment:
#   HCW_REPO      GitHub repository (default hitechcloud-vietnam/HiTechCloudWAF)
#   GITHUB_TOKEN  needed when the repository is private
#   HCW_ROOT      install under this prefix (testing)
set -euo pipefail

REPO=${HCW_REPO:-hitechcloud-vietnam/HiTechCloudWAF}
ROOT=${HCW_ROOT:-}
VERSION=latest
BINARY=""
START=1
ROLE=${1:-}
[ -n "$ROLE" ] && shift || true

GEOIP=0 PUBLIC_CIDR="" CONTROLLER="" NODE_TOKEN="" DNS_TOKEN="" CA="" REGION="" POOLS="default" IPV4=""
NAME="" IP="" ZONE="" NS=""

die() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION=$2; shift 2 ;;
    --binary) BINARY=$2; shift 2 ;;
    --no-start) START=0; shift ;;
    --public-console) PUBLIC_CIDR=$2; shift 2 ;;
    --geoip) GEOIP=1; shift ;;
    --controller) CONTROLLER=$2; shift 2 ;;
    --node-token) NODE_TOKEN=$2; shift 2 ;;
    --node-token-file) NODE_TOKEN=$(cat "$2") || exit 1; shift 2 ;;
    --dns-token) DNS_TOKEN=$2; shift 2 ;;
    --dns-token-file) DNS_TOKEN=$(cat "$2") || exit 1; shift 2 ;;
    --ca) CA=$2; shift 2 ;;
    --region) REGION=$2; shift 2 ;;
    --pools) POOLS=$2; shift 2 ;;
    --ipv4) IPV4=$2; shift 2 ;;
    --name) NAME=$2; shift 2 ;;
    --ip) IP=$2; shift 2 ;;
    --zone) ZONE=$2; shift 2 ;;
    --ns) NS=$2; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done

case "$ROLE" in node|agent|controller|dns) ;; *) sed -n '2,20p' "$0"; exit 2 ;; esac
if [ -z "$ROOT" ] && [ "$(id -u)" != 0 ]; then die "run as root"; fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

randtok() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }

fetch() { # fetch <asset> <dest>
  local url
  if [ "$VERSION" = latest ]; then url="https://github.com/$REPO/releases/latest/download/$1"
  else url="https://github.com/$REPO/releases/download/$VERSION/$1"; fi
  info "downloading $url"
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    # Private repositories: resolve the asset through the API. The token is
    # passed in a header file so it does not show up in the process list.
    local api="https://api.github.com/repos/$REPO/releases/latest"
    [ "$VERSION" != latest ] && api="https://api.github.com/repos/$REPO/releases/tags/$VERSION"
    local id hdr
    hdr=$(mktemp); chmod 600 "$hdr"
    printf 'Authorization: Bearer %s\n' "$GITHUB_TOKEN" > "$hdr"
    id=$(curl -fsSL -H @"$hdr" "$api" | python3 -c '
import json, sys
for a in json.load(sys.stdin).get("assets", []):
    if a["name"] == sys.argv[1]:
        print(a["id"])' "$1")
    [ -n "$id" ] || { rm -f "$hdr"; die "asset $1 not found in release $VERSION"; }
    curl -fsSL -H @"$hdr" -H "Accept: application/octet-stream" \
      "https://api.github.com/repos/$REPO/releases/assets/$id" -o "$2" || { rm -f "$hdr"; die "download of $1 failed"; }
    rm -f "$hdr"
  else
    curl -fsSL "$url" -o "$2"
  fi
}

SUMS=""
verify() { # verify <asset> <file>: compare with the release SHA256SUMS
  if [ -z "$SUMS" ]; then SUMS=$(mktemp); fetch SHA256SUMS "$SUMS"; fi
  local want got
  want=$(awk -v n="$1" '$2 == n || $2 == "*" n {print $1}' "$SUMS")
  [ -n "$want" ] || { echo "error: $1 is not listed in SHA256SUMS" >&2; return 1; }
  got=$(sha256sum "$2" | awk '{print $1}')
  [ "$want" = "$got" ] && info "checksum ok ($1)"
}

install_bin() { # install_bin <name> <asset>
  local dest="$ROOT/usr/local/bin/$1"
  mkdir -p "$ROOT/usr/local/bin"
  if [ -n "$BINARY" ]; then install -m 0755 "$BINARY" "$dest"
  else
    local tmp; tmp=$(mktemp); fetch "$2" "$tmp"
    verify "$2" "$tmp" || { rm -f "$tmp"; die "checksum mismatch for $2"; }
    install -m 0755 "$tmp" "$dest"; rm -f "$tmp"
  fi
  info "installed $dest"
}

ensure_user() { # ensure_user <name>
  [ -n "$ROOT" ] && return 0
  id "$1" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$1"
}

write_unit() { # write_unit <unit> <user> <exec> <caps> <state dir name>
  local f="$ROOT/etc/systemd/system/$1.service"
  mkdir -p "$(dirname "$f")"
  cat > "$f" <<EOF
[Unit]
Description=HiTechCloud WAF – $1
After=network-online.target
Wants=network-online.target

[Service]
User=$2
ExecStart=$3
Restart=always
RestartSec=3
LimitNOFILE=131072
AmbientCapabilities=$4
CapabilityBoundingSet=$4
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/$5
StateDirectory=$5
StateDirectoryMode=0700

[Install]
WantedBy=multi-user.target
EOF
  info "wrote $f"
}

start_unit() {
  [ "$START" = 1 ] && [ -z "$ROOT" ] || return 0
  systemctl daemon-reload
  systemctl enable --now "$1"
  sleep 2
  systemctl --no-pager --lines=5 status "$1" || true
}

case "$ROLE" in
node)
  install_bin hcw-waf "hcw-waf-linux-$ARCH"
  ensure_user hcwwaf
  ETC="$ROOT/etc/hcw-waf"; mkdir -p "$ETC"
  [ -s "$ETC/api.token" ] || (umask 077; randtok > "$ETC/api.token")
  LISTEN="127.0.0.1:9443" ALLOW=""
  if [ -n "$PUBLIC_CIDR" ]; then LISTEN="0.0.0.0:9443"; ALLOW="  allow: [$PUBLIC_CIDR]"; fi
  if [ ! -s "$ETC/waf.yaml" ]; then
    cat > "$ETC/waf.yaml" <<EOF
data_dir: /var/lib/hcw-waf
api:
  listen: $LISTEN
  token_file: /etc/hcw-waf/api.token
$ALLOW
events_kept: 5000
events_file: /var/lib/hcw-waf/events.jsonl
brand:
  name: HiTechCloud WAF
  color: "#1D4ED8"
  support_url: https://hitechcloud.vn
acme:
  enabled: false
  email: ""
EOF
  fi
  if [ "$GEOIP" = 1 ]; then
    # DB-IP Country Lite, CC BY 4.0 (https://db-ip.com) – free, no account.
    got=0
    # The file of the current month appears a few days in; fall back to last month.
    for month in "$(date -u +%Y-%m)" "$(date -u -d "$(date -u +%Y-%m-15) -1 month" +%Y-%m 2>/dev/null || true)"; do
      [ -n "$month" ] || continue
      info "downloading DB-IP Country Lite $month"
      if curl -fsSL "https://download.db-ip.com/free/dbip-country-lite-$month.mmdb.gz" | gunzip > "$ETC/country.mmdb.tmp"; then got=1; break; fi
    done
    if [ "$got" = 1 ]; then
      mv "$ETC/country.mmdb.tmp" "$ETC/country.mmdb"
      grep -q '^geoip_db:' "$ETC/waf.yaml" || echo "geoip_db: /etc/hcw-waf/country.mmdb" >> "$ETC/waf.yaml"
    else
      rm -f "$ETC/country.mmdb.tmp"; echo "warning: GeoIP download failed; set geoip_db later" >&2
    fi
  fi
  [ -z "$ROOT" ] && chown -R hcwwaf "$ETC" && chmod 600 "$ETC/api.token"
  write_unit hcw-waf hcwwaf "/usr/local/bin/hcw-waf -config /etc/hcw-waf/waf.yaml" CAP_NET_BIND_SERVICE hcw-waf
  start_unit hcw-waf
  echo
  info "HiTechCloud WAF node is installed."
  echo "    Console:   https://${LISTEN/0.0.0.0/<server-ip>}/"
  echo "    API token: $ETC/api.token"
  [ -z "$PUBLIC_CIDR" ] && echo "    (console only on localhost; use: ssh -L 9443:127.0.0.1:9443 <server>)"
  ;;

agent)
  [ -n "$CONTROLLER" ] && [ -n "$NODE_TOKEN" ] || die "agent needs --controller and --node-token"
  install_bin hcw "hcw-linux-$ARCH"
  ensure_user hcw
  ETC="$ROOT/etc/hcw"; mkdir -p "$ETC/secrets" "$ETC/tls"
  (umask 077; printf '%s\n' "$NODE_TOKEN" > "$ETC/secrets/node.token")
  [ -s "$ROOT/etc/hcw-waf/api.token" ] || die "install the node first (install.sh node)"
  (umask 077; cp "$ROOT/etc/hcw-waf/api.token" "$ETC/secrets/local-engine.token")
  CA_LINE=""
  if [ -n "$CA" ]; then [ "$CA" -ef "$ETC/tls/ca.crt" ] || cp "$CA" "$ETC/tls/ca.crt"; CA_LINE="  controller_ca: /etc/hcw/tls/ca.crt"; fi
  [ -n "$IPV4" ] || IPV4=$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || true)
  [ -n "$IPV4" ] || die "could not detect the public IPv4, pass --ipv4"
  cat > "$ETC/agent.yaml" <<EOF
agent:
  controller_url: $CONTROLLER
$CA_LINE
  node_token_file: /etc/hcw/secrets/node.token
  region: "${REGION}"
  pools: [${POOLS}]
  ipv4: $IPV4
  probe_url: http://$IPV4:80/
  data_dir: /var/lib/hcw
  engine:
    base_url: https://127.0.0.1:9443
    token_file: /etc/hcw/secrets/local-engine.token
    token_header: X-HCW-API-TOKEN
    insecure_skip_verify: true
  apply_config: true
EOF
  [ -z "$ROOT" ] && chown -R hcw "$ETC"
  write_unit hcw-agent hcw "/usr/local/bin/hcw agent -config /etc/hcw/agent.yaml" "" hcw
  start_unit hcw-agent
  info "agent installed; it reports to $CONTROLLER as $IPV4"
  ;;

controller)
  [ -n "$NAME" ] || die "controller needs --name <dns name of the controller>"
  install_bin hcw "hcw-linux-$ARCH"
  ensure_user hcw
  ETC="$ROOT/etc/hcw"; mkdir -p "$ETC/secrets" "$ETC/tls"
  for t in admin node dns primary-engine; do [ -s "$ETC/secrets/$t.token" ] || (umask 077; randtok > "$ETC/secrets/$t.token"); done
  if [ -s "$ROOT/etc/hcw-waf/api.token" ]; then (umask 077; cp "$ROOT/etc/hcw-waf/api.token" "$ETC/secrets/primary-engine.token"); fi
  if [ ! -s "$ETC/tls/ca.key" ]; then
    # Private keys must never be readable by other users, whatever openssl's
    # defaults are.
    OLD_UMASK=$(umask); umask 077
    openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes -keyout "$ETC/tls/ca.key" -out "$ETC/tls/ca.crt" \
      -subj "/O=HiTechCloud WAF/CN=HiTechCloud WAF Cluster CA" >/dev/null 2>&1
    SAN="DNS:$NAME"; [ -n "$IP" ] && SAN="$SAN,IP:$IP"
    openssl req -newkey rsa:2048 -sha256 -nodes -keyout "$ETC/tls/controller.key" -out "$ETC/tls/controller.csr" \
      -subj "/O=HiTechCloud WAF/CN=$NAME" >/dev/null 2>&1
    printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$SAN" > "$ETC/tls/ext.cnf"
    openssl x509 -req -in "$ETC/tls/controller.csr" -CA "$ETC/tls/ca.crt" -CAkey "$ETC/tls/ca.key" -CAcreateserial \
      -days 825 -sha256 -extfile "$ETC/tls/ext.cnf" -out "$ETC/tls/controller.crt" >/dev/null 2>&1
    rm -f "$ETC/tls/controller.csr" "$ETC/tls/ext.cnf"
    chmod 600 "$ETC/tls/ca.key" "$ETC/tls/controller.key"; chmod 644 "$ETC/tls/ca.crt" "$ETC/tls/controller.crt"
    umask "$OLD_UMASK"
  fi
  cat > "$ETC/controller.yaml" <<'EOF'
controller:
  listen: ":7443"
  tls_cert: /etc/hcw/tls/controller.crt
  tls_key: /etc/hcw/tls/controller.key
  state_file: /var/lib/hcw/controller-state.json
  admin_token_file: /etc/hcw/secrets/admin.token
  node_token_file: /etc/hcw/secrets/node.token
  dns_token_file: /etc/hcw/secrets/dns.token
  probe_insecure: true
  primary:
    base_url: https://127.0.0.1:9443
    token_file: /etc/hcw/secrets/primary-engine.token
    token_header: X-HCW-API-TOKEN
    insecure_skip_verify: true
    resources:
      - {name: cert, path: /api/open/cert, key_fields: [domains], ignore_fields: [created_at, updated_at, issuer, not_after], prune: true}
      - {name: site, path: /api/open/site, key_fields: [server_names], ignore_fields: [created_at, updated_at], refs: {cert_id: cert}, prune: true}
  sync_interval: 15s
  brand: {name: HiTechCloud WAF, primary_color: "#1D4ED8", support_url: "https://hitechcloud.vn"}
EOF
  [ -z "$ROOT" ] && chown -R hcw "$ETC/secrets" "$ETC/tls/controller.key" && chmod 644 "$ETC/tls/ca.crt" "$ETC/tls/controller.crt"
  write_unit hcw-controller hcw "/usr/local/bin/hcw controller -config /etc/hcw/controller.yaml" "" hcw
  start_unit hcw-controller
  echo
  info "Controller installed: https://$NAME:7443/  (admin token: $ETC/secrets/admin.token)"
  echo "    Add a node:  install.sh node && install.sh agent --controller https://$NAME:7443 \\"
  echo "                   --node-token \$(cat $ETC/secrets/node.token) --ca $ETC/tls/ca.crt"
  echo "    Add DNS:     install.sh dns --controller https://$NAME:7443 --dns-token \$(cat $ETC/secrets/dns.token) --ca ca.crt --zone ... --ns ..."
  ;;

dns)
  [ -n "$CONTROLLER" ] && [ -n "$DNS_TOKEN" ] && [ -n "$ZONE" ] && [ -n "$NS" ] || die "dns needs --controller --dns-token --zone --ns"
  install_bin hcw "hcw-linux-$ARCH"
  ensure_user hcw
  ETC="$ROOT/etc/hcw"; mkdir -p "$ETC/secrets" "$ETC/tls"
  (umask 077; printf '%s\n' "$DNS_TOKEN" > "$ETC/secrets/dns.token")
  CA_LINE=""
  if [ -n "$CA" ]; then [ "$CA" -ef "$ETC/tls/ca.crt" ] || cp "$CA" "$ETC/tls/ca.crt"; CA_LINE="  controller_ca: /etc/hcw/tls/ca.crt"; fi
  NS_LIST=$(echo "$NS" | sed 's/,/, /g')
  cat > "$ETC/dns.yaml" <<EOF
dns:
  listen: ":53"
  controller_url: $CONTROLLER
$CA_LINE
  token_file: /etc/hcw/secrets/dns.token
  refresh: 5s
  zones:
    - name: $ZONE
      ns: [$NS_LIST]
      ttl: 30
      records:
        # Add the A records of your name servers, then one pool record per
        # customer (or a shared "edge" record customers CNAME to).
        - {name: edge, pool: web, max_answers: 2, fail_open: true}
EOF
  [ -z "$ROOT" ] && chown -R hcw "$ETC"
  write_unit hcw-dns hcw "/usr/local/bin/hcw dns -config /etc/hcw/dns.yaml" CAP_NET_BIND_SERVICE hcw-dns
  start_unit hcw-dns
  info "DNS installed for zone $ZONE (edit $ETC/dns.yaml to add records)"
  ;;
esac
