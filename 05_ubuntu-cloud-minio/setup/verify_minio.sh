#!/usr/bin/env bash
# =====================================================================
#  verify_minio.sh  --  evidence collection for the implementation chapter
#
#  Run on the ubuntu-cloud machine. Every command prints something that
#  belongs in the documentation as a screenshot or a pasted transcript.
# =====================================================================
set -uo pipefail
hr() { printf '\n----- %s -----\n' "$*"; }

hr "address on the cloud segment"
ip -br addr | grep 192.168.40 || echo "NOT FOUND: this machine is not on 192.168.40.0/24"

hr "service state"
systemctl status minio --no-pager | head -12

hr "listening ports (expect 9000 and 9001)"
ss -tlnp | grep -E "9000|9001" || echo "NOT LISTENING"

hr "server certificate"
if [[ -f /etc/minio/certs/public.crt ]]; then
  openssl x509 -in /etc/minio/certs/public.crt -noout -subject -dates -ext subjectAltName
else
  echo "no certificate: running in plain HTTP"
fi

hr "buckets"
mc ls myminio --insecure

hr "device users issued by the PEP"
# This is the evidence that matters for the evaluation. Entries named
# zt-device-10-0-0-2 appear on ALLOW and disappear on DENY, without any
# action taken on this machine.
mc admin user list myminio --insecure
