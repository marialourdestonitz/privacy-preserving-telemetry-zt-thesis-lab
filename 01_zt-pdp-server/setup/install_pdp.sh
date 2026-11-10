#!/bin/bash
# install_pdp.sh - deploy the Zero Trust PDP on zt-pdp-server (Ubuntu 24.04).
#
# Aligned to this server's interfaces: the resource-facing NICs are ens35
# (192.168.30.0/24) and ens36 (192.168.40.0/24); the management/Internet NIC is
# ens37. Run setup_interfaces.sh FIRST (addresses the NICs), then setup_certs.sh,
# then this script.
#
# Idempotent: the WireGuard server key is generated only once, so re-running to
# redeploy code never invalidates the clients' [Peer] PublicKey.
#
# REVISED per the implementation review 2026-07:
#   Finding B: the FORWARD chain default policy is set to DROP (with a single
#              ESTABLISHED,RELATED accept), installed via the wg-zt0 PostUp
#              hooks so it persists across reboots. Without this, forwarding
#              was default-ACCEPT and the per-session iptables rules did not
#              actually gate anything.
#   Finding E: secrets live in /etc/zt-thesis/pdp.env (0600), generated on
#              first run and loaded by systemd via EnvironmentFile. No secret
#              is baked into code or unit files.
#   Repro:     Python dependencies are installed from the pinned
#              requirements.txt (previously an unpinned list that could drift
#              from the versions the thesis reports).
#   Hygiene:   /var/log/zt-thesis is 0750 (baseline logs contain identifiers).

set -e
SRC="${1:-/root/zt-enterprise}"

echo "[1] System packages"
apt-get update -qq
apt-get install -y wireguard iptables python3-pip python3-venv \
                   python3-full openssh-client

echo "[2] Python environment (pinned versions — see requirements.txt)"
mkdir -p /opt/zt-thesis
python3 -m venv /opt/zt-thesis/venv
if [ -f "$SRC/pdp/requirements.txt" ]; then
    /opt/zt-thesis/venv/bin/pip install -q -r "$SRC/pdp/requirements.txt"
else
    echo "WARNING: $SRC/pdp/requirements.txt not found — falling back to" \
         "unpinned installs. The thesis reports pinned versions; fix this."
    /opt/zt-thesis/venv/bin/pip install -q \
        fastapi "uvicorn[standard]" pydantic cryptography requests phe urllib3 pyyaml
fi

echo "[3] WireGuard server (idempotent key)"
umask 077
if [ ! -f /etc/wireguard/server_private.key ]; then
    wg genkey | tee /etc/wireguard/server_private.key | wg pubkey \
        > /etc/wireguard/server_public.key
fi
SERVER_PRIV=$(cat /etc/wireguard/server_private.key)
SERVER_PUB=$(cat /etc/wireguard/server_public.key)

# NAT/MASQUERADE for tunnel clients (10.0.0.0/24) toward the resource segments.
# On zt-pdp-server those are ens35 (192.168.30.x) and ens36 (192.168.40.x).
#
# DEFAULT-DENY (Finding B): FORWARD policy is DROP; the only standing rule is
# ESTABLISHED,RELATED. Everything else is admitted per-session by the PEP's
# per-IP/per-port ACCEPT rules and removed on DENY/expiry/revocation — which
# is what makes the microsegmentation layer a real enforcement layer.
cat > /etc/wireguard/wg-zt0.conf << EOF
[Interface]
Address    = 10.0.0.1/24
ListenPort = 51820
PrivateKey = ${SERVER_PRIV}
PostUp   = iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o ens35 -j MASQUERADE
PostUp   = iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o ens36 -j MASQUERADE
PostUp   = iptables -P FORWARD DROP
PostUp   = iptables -C FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -m state --state ESTABLISHED,RELATED -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o ens35 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o ens36 -j MASQUERADE
EOF
chmod 600 /etc/wireguard/wg-zt0.conf
systemctl enable wg-quick@wg-zt0
systemctl restart wg-quick@wg-zt0

echo "[4] IP forwarding"
sysctl -w net.ipv4.ip_forward=1
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf \
    || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

echo "[5] Directories"
mkdir -p /opt/zt-thesis/pdp /opt/zt-thesis/monitoring \
         /var/lib/zt-thesis /var/log/zt-thesis
chmod 700 /var/lib/zt-thesis
chmod 750 /var/log/zt-thesis   # baseline decision logs contain identifiers

echo "[6] Secrets file (Finding E — generated once, never in code)"
if [ ! -f /etc/zt-thesis/pdp.env ]; then
    mkdir -p /etc/zt-thesis
    cat > /etc/zt-thesis/pdp.env << ENV
# ZT-Thesis PDP secrets — generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by install_pdp.sh.
# Loaded by systemd (EnvironmentFile). Mode 0600. Edit the MinIO admin
# credentials to match your MinIO deployment, then: systemctl restart zt-pdp
ZT_MINIO_ADMIN_USER=admin
ZT_MINIO_ADMIN_PASS=$(openssl rand -base64 18)
ZT_FLASK_ADMIN=$(openssl rand -base64 18)
ZT_NGINX_ADMIN=$(openssl rand -base64 18)
ENV
    chmod 600 /etc/zt-thesis/pdp.env
    echo "    -> /etc/zt-thesis/pdp.env created. IMPORTANT: set the SAME"
    echo "       ZT_MINIO_ADMIN_PASS on the MinIO server, and the SAME admin"
    echo "       tokens on the Flask/nginx resource servers (see the revised"
    echo "       resource-servers guide)."
else
    echo "    -> /etc/zt-thesis/pdp.env exists; leaving it untouched."
fi

echo "[7] Copy source files"
cp "$SRC/pdp/"*.py        /opt/zt-thesis/pdp/
cp "$SRC/monitoring/"*.py /opt/zt-thesis/monitoring/ 2>/dev/null || true

echo "[8] Systemd service (single worker — see review Finding C)"
cat > /etc/systemd/system/zt-pdp.service << 'UNIT'
[Unit]
Description=Zero Trust Policy Decision Point
After=network-online.target wg-quick@wg-zt0.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/zt-thesis/pdp
ExecStart=/opt/zt-thesis/venv/bin/python pdp_server.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
EnvironmentFile=/etc/zt-thesis/pdp.env
Environment="ZT_CERT_DIR=/etc/zt-thesis/certs"
Environment="ZT_LOG_DIR=/var/log/zt-thesis"
Environment="ZT_WG_IFACE=wg-zt0"

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable zt-pdp
systemctl restart zt-pdp

echo
echo "[9] Verify default-deny (Finding B)"
iptables -S FORWARD | head -3
echo "    ^ expect: -P FORWARD DROP, then the ESTABLISHED,RELATED accept."
echo

echo "Installation complete"
echo "PDP:       https://0.0.0.0:8443"
echo "WireGuard: wg-zt0 - 10.0.0.1/24  (NAT via ens35, ens36; FORWARD default-deny)"
echo "Server WireGuard public key:"
echo "$SERVER_PUB"
