#!/bin/bash
# setup_interfaces.sh - configure the Zero Trust PDP server's network interfaces.
# Ubuntu 24.04 LTS / Netplan (systemd-networkd renderer).
#
# WHAT THIS DOES
#   The PDP is the .1 gateway on every lab segment and routes WireGuard client
#   traffic (10.0.0.0/24, arriving on wg-zt0) to the protected resource subnets.
#   This script writes a persistent Netplan config, enables IPv4 forwarding, and
#   applies it safely (auto-reverting if it would cut your connection).
#
# WHAT THIS DOES *NOT* DO
#   The WireGuard tunnel (wg-zt0) and its NAT/MASQUERADE rules are created by
#   install_pdp.sh / wg-quick, not here. Run setup_certs.sh and install_pdp.sh
#   separately. This script only handles the physical interfaces + forwarding.
#
# *** READ THIS BEFORE RUNNING ***
#   Interface names (ensXX) are assigned by the hypervisor in network-adapter
#   order and WILL differ between machines. Run `ip -br link` first and edit the
#   CONFIG section below to match YOUR actual NIC names. The mapping shipped here
#   is INFERRED from this project (ens38/ens39 are the resource-facing NATed
#   interfaces, per install_pdp.sh) and the client-facing names are placeholders
#   you MUST confirm. Getting this wrong over SSH can lock you out — the script
#   uses `netplan try`, which auto-reverts after 120 s if you do not confirm.

set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo $0)."; exit 1; }

echo "=================================================================="
echo " Current interfaces — map THESE names to the subnets in CONFIG:"
echo "=================================================================="
ip -br link
echo
echo " Current addresses:"
ip -br addr
echo

# ======================= CONFIG — EDIT TO MATCH YOUR VM =====================
# Mapping set for THIS server (zt-pdp-server): NICs are ens33-ens37.
# ens37 is your live management/SSH interface (192.168.1.15 via DHCP) and is
# deliberately NOT touched here — it stays managed by your existing netplan so
# you do not lose your SSH session. Set an interface to "" to skip a segment.
#
# *** You MUST still confirm which VMnet each ens33-ens36 is wired to ***
# (the IP-to-segment assignment below is a sensible default, not verified).

# Management/Internet interface — left to existing config, so skipped here.
WAN_IFACE=""

# Client-facing segments  ── CONFIRM each NIC is on the stated VMnet ──
TRUSTED_IFACE="ens33";  TRUSTED_ADDR="192.168.10.1/24"   # VMnet1 (clients, zt-ep-01)
CLIENT2_IFACE="ens34";  CLIENT2_ADDR="192.168.20.1/24"   # VMnet2 (clients, zt-ep-02)

# Resource-server segments ── these become the NAT/MASQUERADE uplinks ──
ONPREM_IFACE="ens35";   ONPREM_ADDR="192.168.30.1/24"    # on-prem resources
CLOUD_IFACE="ens36";    CLOUD_ADDR="192.168.40.1/24"     # cloud resources
# ===========================================================================

NETPLAN_FILE="/etc/netplan/01-zt-pdp.yaml"
BACKUP_DIR="/etc/netplan/backup-$(date +%Y%m%d-%H%M%S)"

echo "== Backing up existing netplan to $BACKUP_DIR =="
mkdir -p "$BACKUP_DIR"
cp -a /etc/netplan/*.yaml "$BACKUP_DIR"/ 2>/dev/null || true

# Helper: emit a static-address ethernet block (skips empty interface names)
emit_static () {   # $1 = iface   $2 = cidr
    [ -n "$1" ] || return 0
    printf '    %s:\n      dhcp4: false\n      addresses: [%s]\n' "$1" "$2"
}

echo "== Writing $NETPLAN_FILE =="
{
    printf 'network:\n  version: 2\n  renderer: networkd\n  ethernets:\n'
    [ -n "$WAN_IFACE" ] && printf '    %s:\n      dhcp4: true\n' "$WAN_IFACE"
    emit_static "$TRUSTED_IFACE" "$TRUSTED_ADDR"
    emit_static "$CLIENT2_IFACE" "$CLIENT2_ADDR"
    emit_static "$ONPREM_IFACE"  "$ONPREM_ADDR"
    emit_static "$CLOUD_IFACE"   "$CLOUD_ADDR"
} > "$NETPLAN_FILE"
chmod 600 "$NETPLAN_FILE"
echo "------------------------------------------------------------------"
cat "$NETPLAN_FILE"
echo "------------------------------------------------------------------"

echo "== Enabling IPv4 forwarding (so the PDP routes between segments) =="
sysctl -w net.ipv4.ip_forward=1
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf \
    || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

echo "== Validating Netplan syntax =="
netplan generate

echo
echo "== Applying with auto-revert safety =="
echo "   'netplan try' will apply the config and wait up to 120 s."
echo "   If your connection still works, press ENTER to keep it."
echo "   If you LOSE connectivity, do nothing — it reverts automatically."
echo
netplan try || { echo "Reverted or failed. Review $NETPLAN_FILE and the backup in $BACKUP_DIR"; exit 1; }

echo
echo "== Done. Resulting addresses: =="
ip -br addr
echo
echo "Next: run setup_certs.sh, then install_pdp.sh (which creates wg-zt0 and the NAT rules)."
