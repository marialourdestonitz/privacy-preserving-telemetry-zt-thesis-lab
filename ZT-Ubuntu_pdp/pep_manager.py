#!/usr/bin/env python3
"""
pep_manager.py — Policy Enforcement Point coordinator.

Implements four enforcement back-ends invoked by the PDP:

    1. WireGuard peer add/remove   (data-plane tunnel admission)
    2. iptables microsegmentation  (per-IP, per-port ACCEPT rules)
    3. Cloud credential lifecycle  (MinIO keys, Flask bearer tokens,
                                    nginx WebDAV allowlist)

The PDP calls enforce_allow() on ALLOW decisions and enforce_deny() on
DENY decisions, expiry, and explicit revocation. Every operation is
idempotent — calling enforce_deny() on a non-existing peer is a no-op.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
from typing import Iterable

import requests

log = logging.getLogger("pep")

# ---------------------------------------------------------------------------
# Configurable endpoints — adjust if your lab uses different IPs/ports
# ---------------------------------------------------------------------------
MINIO_API_URL     = "http://192.168.40.10:9000"
MINIO_ADMIN_USER  = "admin"
MINIO_ADMIN_PASS  = "Thesis2025!"
MINIO_ALIAS       = "myminio"

FLASK_REVOKE_URL  = "https://192.168.40.10:443/admin/revoke"
FLASK_ISSUE_URL   = "https://192.168.40.10:443/admin/issue"
FLASK_ADMIN_TOKEN = os.environ.get("ZT_FLASK_ADMIN", "thesis-admin-token-2025")

NGINX_ALLOW_URL   = "http://192.168.40.20:8081/admin/allowlist"
NGINX_ADMIN_TOKEN = os.environ.get("ZT_NGINX_ADMIN", "thesis-admin-token-2025")

CA_BUNDLE = "/etc/zt-thesis/certs/ca.crt"


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a subprocess and log on failure."""
    log.debug("$ %s", " ".join(cmd))
    cp = subprocess.run(cmd, capture_output=True, text=True)
    if check and cp.returncode != 0:
        log.error("cmd failed: %s -- %s", " ".join(cmd), cp.stderr.strip())
    return cp


# ===========================================================================
class PEPManager:
    """Coordinates all four enforcement back-ends, serialised by a lock."""

    def __init__(self, wg_iface: str = "wg0"):
        self.wg_iface = wg_iface
        self._lock = threading.Lock()
        # Track issued cloud creds so we can revoke without re-querying state.
        # key = tunnel_ip, value = {'minio_key', 'flask_token', 'webdav_ip'}
        self._cloud_state: dict[str, dict[str, str]] = {}

    # ------------------------------------------------------------------ ALLOW
    def enforce_allow(self,
                      tunnel_ip: str,
                      wg_pubkey: str,
                      scopes: Iterable[str],
                      scope_to_target: dict[str, tuple[str, list[int]]]) -> None:
        scopes = list(scopes)
        with self._lock:
            log.info("ALLOW %s scopes=%s", tunnel_ip, scopes)
            self._wg_add_peer(tunnel_ip, wg_pubkey)
            self._flush_peer_iptables(tunnel_ip)
            for s in scopes:
                tgt, ports = scope_to_target.get(s, (None, []))
                if not tgt:
                    continue
                for p in ports:
                    self._iptables_allow(tunnel_ip, tgt, p)
                # Cloud-specific provisioning
                if s == "s3":
                    self._minio_issue(tunnel_ip)
                elif s == "rest":
                    self._flask_issue(tunnel_ip)
                elif s == "webdav":
                    self._nginx_allow(tunnel_ip)

    # ------------------------------------------------------------------- DENY
    def enforce_deny(self,
                     tunnel_ip: str,
                     wg_pubkey: str,
                     scopes: Iterable[str],
                     scope_to_target: dict[str, tuple[str, list[int]]]) -> None:
        scopes = list(scopes)
        with self._lock:
            log.info("DENY %s scopes=%s", tunnel_ip, scopes)
            self._flush_peer_iptables(tunnel_ip)
            self._wg_remove_peer(wg_pubkey)
            # Revoke every cloud credential we issued for this tunnel
            state = self._cloud_state.pop(tunnel_ip, {})
            if state.get("minio_key"):
                self._minio_revoke(state["minio_key"])
            if state.get("flask_token"):
                self._flask_revoke(state["flask_token"])
            if "webdav" in scopes or state.get("webdav_ip"):
                self._nginx_deny(tunnel_ip)

    # ===================================================================
    # WireGuard
    # ===================================================================
    def _wg_add_peer(self, tunnel_ip: str, pubkey: str) -> None:
        _run(["wg", "set", self.wg_iface,
              "peer", pubkey,
              "allowed-ips", f"{tunnel_ip}/32",
              "persistent-keepalive", "25"], check=False)

    def _wg_remove_peer(self, pubkey: str) -> None:
        if not pubkey:
            return
        _run(["wg", "set", self.wg_iface, "peer", pubkey, "remove"], check=False)

    # ===================================================================
    # iptables — microsegmentation
    # ===================================================================
    def _iptables_allow(self, src_ip: str, dst_cidr: str, dport: int) -> None:
        cmd = ["iptables", "-C", "FORWARD",
               "-s", src_ip, "-d", dst_cidr, "-p", "tcp",
               "--dport", str(dport), "-j", "ACCEPT"]
        if _run(cmd, check=False).returncode != 0:
            _run(["iptables", "-A", "FORWARD",
                  "-s", src_ip, "-d", dst_cidr, "-p", "tcp",
                  "--dport", str(dport), "-j", "ACCEPT"], check=False)

    def _flush_peer_iptables(self, src_ip: str) -> None:
        """Delete every FORWARD rule with -s <src_ip>."""
        out = _run(["iptables", "-S", "FORWARD"], check=False).stdout
        for line in out.splitlines():
            if f" -s {src_ip}/32 " in line and line.startswith("-A FORWARD"):
                rule = line.replace("-A FORWARD", "FORWARD", 1).split()
                _run(["iptables", "-D"] + rule, check=False)

    # ===================================================================
    # MinIO — issue/revoke per-tunnel access keys
    # ===================================================================
    def _minio_alias(self) -> bool:
        cp = _run(["mc", "alias", "set", MINIO_ALIAS, MINIO_API_URL,
                   MINIO_ADMIN_USER, MINIO_ADMIN_PASS], check=False)
        return cp.returncode == 0

    def _minio_issue(self, tunnel_ip: str) -> None:
        if not self._minio_alias():
            log.warning("MinIO alias failed; skipping issue")
            return
        access_key = f"zt-device-{tunnel_ip.replace('.', '-')}"
        secret_key = "TempPass!2025"
        # `mc admin user add` is idempotent: ignore the duplicate-user error
        _run(["mc", "admin", "user", "add", MINIO_ALIAS,
              access_key, secret_key], check=False)
        _run(["mc", "admin", "policy", "attach", MINIO_ALIAS,
              "readwrite", "--user", access_key], check=False)
        self._cloud_state.setdefault(tunnel_ip, {})["minio_key"] = access_key
        log.info("MinIO key issued: %s", access_key)

    def _minio_revoke(self, access_key: str) -> None:
        if not self._minio_alias():
            return
        _run(["mc", "admin", "user", "remove", MINIO_ALIAS, access_key],
             check=False)
        log.info("MinIO key revoked: %s", access_key)

    # ===================================================================
    # Flask REST — issue/revoke bearer tokens
    # ===================================================================
    def _flask_issue(self, tunnel_ip: str) -> None:
        try:
            r = requests.post(
                FLASK_ISSUE_URL,
                json={"tunnel_ip": tunnel_ip},
                headers={"X-Admin-Token": FLASK_ADMIN_TOKEN},
                verify=CA_BUNDLE, timeout=5)
            if r.ok:
                tok = r.json().get("token")
                if tok:
                    self._cloud_state.setdefault(tunnel_ip, {})["flask_token"] = tok
                    log.info("Flask token issued for %s", tunnel_ip)
        except Exception as e:
            log.warning("Flask issue failed: %s", e)

    def _flask_revoke(self, token: str) -> None:
        try:
            requests.post(FLASK_REVOKE_URL,
                          json={"token": token},
                          headers={"X-Admin-Token": FLASK_ADMIN_TOKEN},
                          verify=CA_BUNDLE, timeout=5)
            log.info("Flask token revoked")
        except Exception as e:
            log.warning("Flask revoke failed: %s", e)

    # ===================================================================
    # nginx WebDAV — IP allowlist
    # ===================================================================
    def _nginx_allow(self, tunnel_ip: str) -> None:
        try:
            r = requests.post(NGINX_ALLOW_URL,
                              json={"ip": tunnel_ip},
                              headers={"X-Admin-Token": NGINX_ADMIN_TOKEN},
                              timeout=5)
            if r.ok:
                self._cloud_state.setdefault(tunnel_ip, {})["webdav_ip"] = tunnel_ip
                log.info("nginx allowlist: added %s", tunnel_ip)
        except Exception as e:
            log.warning("nginx allow failed: %s", e)

    def _nginx_deny(self, tunnel_ip: str) -> None:
        try:
            requests.delete(f"{NGINX_ALLOW_URL}/{tunnel_ip}",
                            headers={"X-Admin-Token": NGINX_ADMIN_TOKEN},
                            timeout=5)
            log.info("nginx allowlist: removed %s", tunnel_ip)
        except Exception as e:
            log.warning("nginx deny failed: %s", e)
