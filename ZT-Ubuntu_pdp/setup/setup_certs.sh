#!/usr/bin/env bash

#  Generates:
#    /etc/zt-thesis/certs/ca.{key,crt}                
#    /etc/zt-thesis/certs/pdp.{key,crt}                 
#    /etc/zt-thesis/certs/client-a.{key,crt,pfx}
#    /etc/zt-thesis/certs/client-b.{key,crt,pfx}
#    /etc/zt-thesis/certs/cloud.{key,crt}     
        
set -euo pipefail

CERT_DIR="/etc/zt-thesis/certs"
PFX_PASS="${PFX_PASS:-Thesis2025!}"
PDP_IP="192.168.10.1"
PDP_DNS="ubuntu-pdp.lab.local"
DAYS_CA=3650
DAYS_LEAF=825

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"
umask 077

#Generating RSA-4096 root CA
openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS_CA" \
    -subj "/C=AT/ST=Vienna/O=ZT-Thesis-Lab/OU=PKI/CN=ZT-Thesis Root CA" \
    -out ca.crt

#Generating PDP server certificate
cat > pdp.cnf <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn
[dn]
C = AT
ST = Vienna
O = ZT-Thesis-Lab
OU = PDP
CN = $PDP_DNS
[req_ext]
subjectAltName = @alt_names
[alt_names]
DNS.1 = $PDP_DNS
DNS.2 = ubuntu-pdp
DNS.3 = localhost
IP.1  = $PDP_IP
IP.2  = 127.0.0.1
IP.3  = 10.0.0.1
EOF
openssl genrsa -out pdp.key 2048 2>/dev/null
openssl req -new -key pdp.key -out pdp.csr -config pdp.cnf
openssl x509 -req -in pdp.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out pdp.crt -days "$DAYS_LEAF" -sha256 \
    -extfile pdp.cnf -extensions req_ext

#cert and pfx with given CN
make_client() {
    local CN="$1"
    echo "[*] Generating client certificate: $CN"
    openssl genrsa -out "${CN}.key" 2048 2>/dev/null
    openssl req -new -key "${CN}.key" -out "${CN}.csr" \
        -subj "/C=AT/ST=Vienna/O=ZT-Thesis-Lab/OU=Endpoints/CN=${CN}"
    openssl x509 -req -in "${CN}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out "${CN}.crt" -days "$DAYS_LEAF" -sha256
    # PFX bundle for Windows clients to LocalMachine
    openssl pkcs12 -export -out "${CN}.pfx" \
        -inkey "${CN}.key" -in "${CN}.crt" -certfile ca.crt \
        -password "pass:${PFX_PASS}"
}

make_client "client-a"
make_client "client-b"

#Generating ubuntu-cloud TLS certificate
cat > cloud.cnf <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn
[dn]
C = AT
O = ZT-Thesis-Lab
CN = ubuntu-cloud.lab.local
[req_ext]
subjectAltName = @alt_names
[alt_names]
DNS.1 = ubuntu-cloud.lab.local
IP.1  = 192.168.40.10
IP.2  = 192.168.40.20
EOF
openssl genrsa -out cloud.key 2048 2>/dev/null
openssl req -new -key cloud.key -out cloud.csr -config cloud.cnf
openssl x509 -req -in cloud.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out cloud.crt -days "$DAYS_LEAF" -sha256 \
    -extfile cloud.cnf -extensions req_ext

# Cleanup CSRs
rm -f ./*.csr ./pdp.cnf ./cloud.cnf

#Permissions: keys readable by root only and certs world-readable for distribution
chmod 600 ./*.key
chmod 644 ./*.crt ./*.pfx
chown -R root:root "$CERT_DIR"

ls -la "$CERT_DIR"


