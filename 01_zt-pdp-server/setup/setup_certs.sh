#!/bin/bash
# setup_certs.sh - generate the mTLS PKI for zt-pdp-server.
#
# Trust is CA-based: the PDP accepts any client certificate signed by ca.crt,
# so re-issuing a client cert needs no PDP change. Run this BEFORE install_pdp.sh.
#
# The PDP server certificate's SAN lists every address a client may use to reach
# the PDP API (port 8443): its .1 address on each lab segment, the tunnel
# address, and the management IP. The lab subnets are unchanged from before; only
# the NIC names differ on this box, and NIC names do not appear in certificates.

set -e
CERT_DIR=/etc/zt-thesis/certs
PDP_SANS="DNS:zt-pdp-server,IP:10.0.0.1,IP:192.168.10.1,IP:192.168.20.1,IP:192.168.30.1,IP:192.168.40.1,IP:192.168.1.15"
# Review fix (Finding E): no hardcoded PFX passphrase. Supply via env
# (ZT_PFX_PASS) or let the script generate a random one and print it ONCE.
PFX_PASS="${ZT_PFX_PASS:-$(openssl rand -base64 12)}"

mkdir -p "$CERT_DIR"; cd "$CERT_DIR"; umask 077

# --- CA (generated only if absent, so re-running keeps client trust valid) ---
if [ ! -f ca.crt ]; then
  openssl genrsa -out ca.key 4096
  openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
    -subj "/C=AT/O=MasterThesis/CN=ZT-Thesis-CA" -out ca.crt
  echo "[*] Created new CA (ca.crt)."
else
  echo "[*] Reusing existing CA (ca.crt)."
fi

# --- PDP server certificate (regenerated each run; SAN = all PDP-reachable IPs) ---
openssl genrsa -out pdp.key 4096
openssl req -new -key pdp.key -subj "/C=AT/O=MasterThesis/CN=zt-pdp-server" -out pdp.csr
openssl x509 -req -in pdp.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -sha256 -extfile <(printf "subjectAltName=%s" "$PDP_SANS") -out pdp.crt
rm -f pdp.csr
echo "[*] Issued PDP server cert (pdp.crt) with SAN: $PDP_SANS"

# --- client certificates (CN distinguishes identity to the agent) ---
for c in client-a client-b; do
  openssl genrsa -out "$c.key" 2048
  openssl req -new -key "$c.key" -subj "/C=AT/O=MasterThesis/CN=$c" -out "$c.csr"
  openssl x509 -req -in "$c.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 825 -sha256 -out "$c.crt"
  openssl pkcs12 -export -out "$c.pfx" -inkey "$c.key" -in "$c.crt" \
    -certfile ca.crt -passout pass:"$PFX_PASS"
  rm -f "$c.csr"
  echo "[*] Issued $c.pfx"
done

chmod 600 "$CERT_DIR"/*.key "$CERT_DIR"/*.pfx
echo
echo "Certs written to $CERT_DIR (PFX passphrase: $PFX_PASS)"
echo "Distribute: ca.crt + client-a.pfx -> Client A; ca.crt + client-b.pfx -> Client B."
