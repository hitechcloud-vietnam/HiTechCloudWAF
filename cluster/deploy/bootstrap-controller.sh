#!/bin/sh
# Prepares /etc/hcw on the control-plane host: tokens, a private CA and the
# controller TLS certificate. Re-running keeps existing secrets.
#
#   sudo ./bootstrap-controller.sh controller.example.vn 203.0.113.5
set -eu

NAME=${1:?usage: $0 <controller-dns-name> [controller-ip]}
IP=${2:-}
ETC=${HCW_ETC:-/etc/hcw}

umask 077
mkdir -p "$ETC/secrets" "$ETC/tls" /var/lib/hcw
chown 10001 /var/lib/hcw 2>/dev/null || true

for t in admin node dns; do
  f="$ETC/secrets/$t.token"
  [ -s "$f" ] || openssl rand -hex 32 > "$f"
done

if [ ! -s "$ETC/tls/ca.key" ]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
    -keyout "$ETC/tls/ca.key" -out "$ETC/tls/ca.crt" \
    -subj "/O=HiTechCloud WAF/CN=HiTechCloud WAF Cluster CA" >/dev/null 2>&1
fi

if [ ! -s "$ETC/tls/controller.crt" ]; then
  SAN="DNS:$NAME"
  [ -n "$IP" ] && SAN="$SAN,IP:$IP"
  openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout "$ETC/tls/controller.key" -out "$ETC/tls/controller.csr" \
    -subj "/O=HiTechCloud WAF/CN=$NAME" >/dev/null 2>&1
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$SAN" > "$ETC/tls/ext.cnf"
  openssl x509 -req -in "$ETC/tls/controller.csr" -CA "$ETC/tls/ca.crt" -CAkey "$ETC/tls/ca.key" \
    -CAcreateserial -days 825 -sha256 -extfile "$ETC/tls/ext.cnf" -out "$ETC/tls/controller.crt" >/dev/null 2>&1
  rm -f "$ETC/tls/controller.csr" "$ETC/tls/ext.cnf"
fi

# The controller runs as uid 10001 and must read its key and tokens.
chown -R 10001 "$ETC/secrets" "$ETC/tls/controller.key" 2>/dev/null || true
chmod 644 "$ETC/tls/ca.crt" "$ETC/tls/controller.crt"

echo "Done. Copy to every node:   $ETC/tls/ca.crt  $ETC/secrets/node.token"
echo "Copy to every DNS server:   $ETC/tls/ca.crt  $ETC/secrets/dns.token"
echo "Dashboard admin token:      $ETC/secrets/admin.token"
