#!/usr/bin/env python3
"""
webdav_admin.py - allowlist admin + authorization service for the WebDAV plane.

This is the server side of the NGINX_ALLOW_URL endpoints that pep_manager.py
calls. It runs on the WebDAV resource host (192.168.40.20), bound to localhost;
nginx terminates TLS (:8444 for the admin API, :443 for WebDAV) and reverse-
proxies to it, so the PEP reaches it as https://192.168.40.20:8444/... exactly
as configured (review Finding F: HTTPS + lab CA).

Contract (must match pep_manager.py):
  POST   /admin/allowlist        header X-Admin-Token: <ZT_NGINX_ADMIN>
                                 body  {"ip": "10.0.0.2"}
                                 ->    {"allowed": "10.0.0.2"}
  DELETE /admin/allowlist/<ip>   header X-Admin-Token: <ZT_NGINX_ADMIN>
                                 ->    {"removed": true|false}

Plus the hook nginx uses to actually GATE WebDAV (no nginx reload needed):
  GET    /authz                  nginx auth_request subrequest;
                                 200 if the original client IP is allowlisted,
                                 403 otherwise. nginx passes the client IP in
                                 the X-Original-IP header (see nginx-webdav.conf).

Design notes for the thesis:
  * Admin secret from the environment (ZT_NGINX_ADMIN) - the SAME value set in
    /etc/zt-thesis/pdp.env on the PDP. No hardcoded secret (review Finding E).
  * Allowlist is in-memory: correct for the single-process lab; a restart
    clears it (fail-safe: everything is denied until the PEP re-allows).
  * Using auth_request instead of rewriting an nginx allow/deny file means the
    PEP's add/remove take effect immediately with no nginx reload.

  TOPOLOGY CAVEAT (document in the thesis / verify in the lab): the PEP allows
  by TUNNEL IP (10.0.0.2). nginx must therefore SEE the client as 10.0.0.2. If
  the PDP masquerades tunnel->resource traffic (the POSTROUTING MASQUERADE in
  install_pdp.sh), nginx sees the PDP's segment IP instead, and the allowlist
  will not match. Two options: (a) route (don't NAT) the 10.0.0.0/24 ->
  192.168.40.0/24 path so the real tunnel IP is preserved, or (b) allowlist the
  PDP's resource-facing IP instead of the tunnel IP. Pick one and state it;
  primary enforcement is still the WireGuard peer + iptables layer.
"""
from __future__ import annotations

import hmac
import ipaddress
import os

from flask import Flask, abort, jsonify, request

ADMIN_TOKEN = os.environ.get("ZT_NGINX_ADMIN", "")
BIND_HOST   = os.environ.get("ZT_WEBDAV_ADMIN_BIND", "127.0.0.1")
BIND_PORT   = int(os.environ.get("ZT_WEBDAV_ADMIN_PORT", "5001"))

app = Flask(__name__)
_ALLOW: set[str] = set()   # allowlisted client IPs


def _admin_ok(req) -> bool:
    supplied = req.headers.get("X-Admin-Token", "")
    if not ADMIN_TOKEN:
        app.logger.error("ZT_NGINX_ADMIN not set; refusing all admin calls")
        return False
    return hmac.compare_digest(supplied, ADMIN_TOKEN)


def _valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


@app.post("/admin/allowlist")
def allow():
    if not _admin_ok(request):
        abort(403, "bad admin token")
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "")
    if not _valid_ip(ip):
        abort(400, "valid ip required")
    _ALLOW.add(ip)
    app.logger.info("allowlist add %s (now %d)", ip, len(_ALLOW))
    return jsonify({"allowed": ip})


@app.delete("/admin/allowlist/<ip>")
def deny(ip):
    if not _admin_ok(request):
        abort(403, "bad admin token")
    existed = ip in _ALLOW
    _ALLOW.discard(ip)
    app.logger.info("allowlist remove %s (%s)", ip, "ok" if existed else "absent")
    return jsonify({"removed": existed})


@app.get("/authz")
def authz():
    # nginx auth_request: 200 => allow the WebDAV request, 403 => block it.
    client = request.headers.get("X-Original-IP", request.remote_addr or "")
    if client in _ALLOW:
        return ("", 200)
    return ("", 403)


@app.get("/admin/allowlist")
def listing():
    if not _admin_ok(request):
        abort(403, "bad admin token")
    return jsonify({"allowlist": sorted(_ALLOW)})


@app.get("/health")
def health():
    return jsonify({"status": "ok", "allowlisted": len(_ALLOW)})


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def _err(e):
    return jsonify({"error": getattr(e, "description", str(e))}), e.code


if __name__ == "__main__":
    if not ADMIN_TOKEN:
        print("WARNING: ZT_NGINX_ADMIN is not set - admin endpoints will reject "
              "every call. Export it (same value as on the PDP) before serving.")
    print(f"WebDAV allowlist admin on http://{BIND_HOST}:{BIND_PORT}; "
          f"front with nginx TLS (:8444 admin, :443 WebDAV auth_request)")
    app.run(host=BIND_HOST, port=BIND_PORT)
