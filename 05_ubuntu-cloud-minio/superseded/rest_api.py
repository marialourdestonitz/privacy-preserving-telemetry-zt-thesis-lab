#!/usr/bin/env python3
"""
rest_api.py - the cloud REST resource server for the ZT thesis lab.

This is the server side of the endpoints that pep_manager.py already calls.
It runs on the cloud resource host (ubuntu-cloud, 192.168.40.10), bound to
localhost only; nginx terminates TLS on :443 and reverse-proxies to it, so the
PEP reaches it as https://192.168.40.10:443/... exactly as configured.

Contract (must match pep_manager.py):
  POST /admin/issue    header X-Admin-Token: <ZT_FLASK_ADMIN>
                       body  {"tunnel_ip": "10.0.0.2"}
                       ->    {"token": "<bearer>"}            (PEP stores it)
  POST /admin/revoke   header X-Admin-Token: <ZT_FLASK_ADMIN>
                       body  {"token": "<bearer>"}
                       ->    {"revoked": true}
  GET  /files/<name>   header Authorization: Bearer <token>
                       ->    the file bytes (the protected resource)

Design notes for the thesis:
  * The admin token is the shared secret between the PDP's PEP and this server;
    it comes from the environment (ZT_FLASK_ADMIN), the SAME value set in
    /etc/zt-thesis/pdp.env on the PDP. No secret is hardcoded (review Finding E).
  * Issued bearer tokens are random (secrets.token_urlsafe) and mapped to the
    tunnel_ip that was granted, so a token proves "the PDP admitted this device
    for cloud REST access". Revocation deletes the mapping -> the token is dead
    immediately, which is how a DENY/expiry severs cloud access.
  * Token store is in-memory (a dict): correct for the single-process lab and
    it means a server restart revokes everything, which is acceptable here.
    For production it would move to a shared store (noted as future work).
  * Admin-token comparison is constant-time (hmac.compare_digest).
"""
from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory

# --- config (from environment; matches pdp.env on the PDP) ------------------
ADMIN_TOKEN = os.environ.get("ZT_FLASK_ADMIN", "")
FILES_DIR   = Path(os.environ.get("ZT_FILES_DIR",
                                  Path(__file__).resolve().parent / "files"))
BIND_HOST   = os.environ.get("ZT_REST_BIND", "127.0.0.1")   # nginx fronts TLS
BIND_PORT   = int(os.environ.get("ZT_REST_PORT", "5000"))

FILES_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

# token -> tunnel_ip  (an issued, not-yet-revoked bearer token)
_TOKENS: dict[str, str] = {}


# --- helpers ----------------------------------------------------------------
def _admin_ok(req) -> bool:
    supplied = req.headers.get("X-Admin-Token", "")
    if not ADMIN_TOKEN:
        app.logger.error("ZT_FLASK_ADMIN not set; refusing all admin calls")
        return False
    return hmac.compare_digest(supplied, ADMIN_TOKEN)


def _bearer(req) -> str | None:
    auth = req.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer "):].strip()
    return None


# --- admin endpoints (called by the PEP, fronted by nginx TLS) --------------
@app.post("/admin/issue")
def issue():
    if not _admin_ok(request):
        abort(403, "bad admin token")
    data = request.get_json(silent=True) or {}
    tunnel_ip = data.get("tunnel_ip")
    if not tunnel_ip:
        abort(400, "tunnel_ip required")
    token = secrets.token_urlsafe(24)
    _TOKENS[token] = tunnel_ip
    app.logger.info("issued REST token for %s", tunnel_ip)
    return jsonify({"token": token})


@app.post("/admin/revoke")
def revoke():
    if not _admin_ok(request):
        abort(403, "bad admin token")
    data = request.get_json(silent=True) or {}
    token = data.get("token")
    existed = _TOKENS.pop(token, None) is not None
    app.logger.info("revoke REST token: %s", "ok" if existed else "unknown")
    return jsonify({"revoked": existed})


# --- protected resource -----------------------------------------------------
@app.get("/files/<path:name>")
def get_file(name):
    token = _bearer(request)
    if not token or token not in _TOKENS:
        abort(401, "missing or revoked bearer token")
    # send_from_directory blocks path traversal (../) safely
    return send_from_directory(FILES_DIR, name, as_attachment=False)


@app.get("/health")
def health():
    return jsonify({"status": "ok", "active_tokens": len(_TOKENS)})


# --- error shape ------------------------------------------------------------
@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
def _err(e):
    return jsonify({"error": getattr(e, "description", str(e))}), e.code


if __name__ == "__main__":
    if not ADMIN_TOKEN:
        print("WARNING: ZT_FLASK_ADMIN is not set - admin endpoints will reject "
              "every call. Export it (same value as on the PDP) before serving.")
    print(f"REST resource server on http://{BIND_HOST}:{BIND_PORT} "
          f"(files: {FILES_DIR}); front with nginx TLS on :443")
    app.run(host=BIND_HOST, port=BIND_PORT)
