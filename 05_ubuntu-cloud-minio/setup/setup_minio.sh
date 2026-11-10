#!/usr/bin/env bash
# =====================================================================
#  setup_minio.sh  --  build the S3 resource plane (ubuntu-cloud VM)
#
#  Master Thesis: Design and Experimental Evaluation of Privacy-Preserving
#  Telemetry for Continuous Verification in Zero Trust Enterprise File Sharing
#  M. L. Tonitz, FH Kaernten
#
#  Run on the ubuntu-cloud machine (192.168.40.10) as root.
#
#  This script is idempotent: re-running it must not change the outcome.
#  That matters because it is re-run whenever the machine is rebuilt, and
#  because the admin credential it writes must survive re-runs. If the
#  credential were regenerated on every install, every PDP that had it
#  configured would start failing authentication, which is the same class
#  of fault recorded as E1 and E8 in the implementation chapter.
#
#  What this machine is
#  --------------------
#  It serves the cloud file-sharing plane over S3. It runs no project code.
#  Whether a client may reach it is decided by the PDP and enforced by the
#  PEP on the network path, from outside this machine. This script therefore
#  builds a plain MinIO deployment and nothing more.
#
#  Contract with the PDP (pep_manager.py)
#  --------------------------------------
#  The PEP mints and revokes per-device access keys here over the admin API
#  using the mc client. Four things must line up, and this script sets all
#  four to the values the PDP already expects:
#
#    ZT_MINIO_URL        http(s)://192.168.40.10:9000   API endpoint
#    ZT_MINIO_ADMIN_USER admin                          root user
#    ZT_MINIO_ADMIN_PASS <written to /etc/minio/admin.env>
#    policy              readwrite                      attached per device
#
#  The admin password written here MUST be copied into
#  /etc/zt-thesis/pdp.env on the PDP. The PDP's environment file is the
#  authoritative source; a divergence produces authentication failures
#  during credential issuance that look like a PEP bug but are not.
# =====================================================================
set -euo pipefail

MINIO_ADDR="192.168.40.10"
API_PORT="9000"
CONSOLE_PORT="9001"
DATA_DIR="/mnt/data"
CERTS_DIR="/etc/minio/certs"
ENV_FILE="/etc/minio/admin.env"
ADMIN_USER="admin"
BUCKETS=("zt-bucket" "enterprise-objects")
ALIAS="myminio"

log() { printf '\n[setup_minio] %s\n' "$*"; }

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

# ---------------------------------------------------------------------
# 1. Binaries
#    The mc client is installed here for local verification. The PDP needs
#    its own copy; that is handled by install_pdp.sh, not by this script.
# ---------------------------------------------------------------------
log "installing binaries"
if [[ ! -x /usr/local/bin/minio ]]; then
  curl -fsSL https://dl.min.io/server/minio/release/linux-amd64/minio \
       -o /usr/local/bin/minio
  chmod +x /usr/local/bin/minio
else
  echo "  minio already present, leaving it alone"
fi
if [[ ! -x /usr/local/bin/mc ]]; then
  curl -fsSL https://dl.min.io/client/mc/release/linux-amd64/mc \
       -o /usr/local/bin/mc
  chmod +x /usr/local/bin/mc
else
  echo "  mc already present, leaving it alone"
fi

# ---------------------------------------------------------------------
# 2. Service account and directories
# ---------------------------------------------------------------------
log "creating service account and directories"
id -u minio-user >/dev/null 2>&1 || useradd -r -s /sbin/nologin minio-user
mkdir -p "$DATA_DIR" "$CERTS_DIR"
chown -R minio-user:minio-user "$DATA_DIR" "$CERTS_DIR"

# ---------------------------------------------------------------------
# 3. Admin credential
#    Generated once, on first run only. See the header for why.
# ---------------------------------------------------------------------
if [[ -f "$ENV_FILE" ]]; then
  log "admin credential already exists, preserving it"
else
  log "generating admin credential (first run)"
  ADMIN_PASS="$(openssl rand -base64 18)"
  cat > "$ENV_FILE" <<EOF
# MinIO root credentials for the thesis laboratory.
# These MUST match ZT_MINIO_ADMIN_USER and ZT_MINIO_ADMIN_PASS in
# /etc/zt-thesis/pdp.env on the PDP. The PDP file is authoritative.
MINIO_ROOT_USER=${ADMIN_USER}
MINIO_ROOT_PASSWORD=${ADMIN_PASS}
EOF
  chmod 600 "$ENV_FILE"
fi
# shellcheck disable=SC1090
source "$ENV_FILE"

# ---------------------------------------------------------------------
# 4. TLS certificate from the laboratory CA
#    Copy ca.crt and ca.key from the PDP (/etc/zt-thesis/certs/) before
#    running this, or place a pre-issued pair in $CERTS_DIR yourself.
#    The address must appear in the subject alternative name, or the
#    client will reject the certificate no matter what the CN says.
# ---------------------------------------------------------------------
if [[ -f "$CERTS_DIR/public.crt" && -f "$CERTS_DIR/private.key" ]]; then
  log "certificate already present, preserving it"
elif [[ -f /tmp/ca.crt && -f /tmp/ca.key ]]; then
  log "issuing server certificate from the laboratory CA"
  openssl genrsa -out /tmp/minio.key 2048
  openssl req -new -key /tmp/minio.key -subj "/CN=zt-cloud" -out /tmp/minio.csr
  openssl x509 -req -in /tmp/minio.csr -CA /tmp/ca.crt -CAkey /tmp/ca.key \
    -CAcreateserial -days 825 -sha256 \
    -extfile <(printf "subjectAltName=IP:%s" "$MINIO_ADDR") \
    -out /tmp/minio.crt
  install -o minio-user -g minio-user -m 644 /tmp/minio.crt "$CERTS_DIR/public.crt"
  install -o minio-user -g minio-user -m 600 /tmp/minio.key "$CERTS_DIR/private.key"
  rm -f /tmp/minio.key /tmp/minio.csr /tmp/minio.crt
else
  log "WARNING: no certificate and no CA material in /tmp"
  echo "  MinIO will start in plain HTTP. Copy ca.crt and ca.key from the PDP"
  echo "  and re-run this script to enable TLS."
fi

# ---------------------------------------------------------------------
# 5. systemd unit
#    Both ports are pinned explicitly in ExecStart rather than passed
#    through a shell variable. An early fault on this machine had the
#    console appearing on a different port after every restart because
#    an options variable was not expanded by systemd; hard-coding the
#    arguments is the correction, recorded as E7.
# ---------------------------------------------------------------------
log "installing systemd unit"
install -m 644 "$(dirname "$0")/minio.service" /etc/systemd/system/minio.service
systemctl daemon-reload
systemctl enable --now minio
sleep 3

# ---------------------------------------------------------------------
# 6. Buckets
#    Created through mc so that the operation is repeatable. --ignore-existing
#    is what makes this step idempotent.
# ---------------------------------------------------------------------
log "configuring alias and buckets"
SCHEME="https"; [[ -f "$CERTS_DIR/public.crt" ]] || SCHEME="http"
mc alias set "$ALIAS" "${SCHEME}://${MINIO_ADDR}:${API_PORT}" \
   "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" --insecure >/dev/null
for b in "${BUCKETS[@]}"; do
  mc mb --ignore-existing "${ALIAS}/${b}" --insecure
done

# ---------------------------------------------------------------------
# 7. Report
# ---------------------------------------------------------------------
log "done"
cat <<EOF

  API endpoint : ${SCHEME}://${MINIO_ADDR}:${API_PORT}
  Console      : ${SCHEME}://${MINIO_ADDR}:${CONSOLE_PORT}
  Buckets      : ${BUCKETS[*]}
  Admin user   : ${MINIO_ROOT_USER}

  NEXT STEP, and the system will not issue credentials without it.
  On the PDP, set these in /etc/zt-thesis/pdp.env and restart zt-pdp:

    ZT_MINIO_URL=${SCHEME}://${MINIO_ADDR}:${API_PORT}
    ZT_MINIO_ADMIN_USER=${MINIO_ROOT_USER}
    ZT_MINIO_ADMIN_PASS=$(grep MINIO_ROOT_PASSWORD "$ENV_FILE" | cut -d= -f2-)

    systemctl restart zt-pdp

EOF
