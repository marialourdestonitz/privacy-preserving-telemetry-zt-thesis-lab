#!/usr/bin/env python3

import json
import logging
import os
import ssl
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request

# Local modules
sys.path.insert(0, str(Path(__file__).resolve().parent))
from privacy_transform import PrivacyTransform           
from he_risk_engine import HERiskEngine                 
from pep_manager import PEPManager                    
from measurement import MeasurementLogger               


# Configuration
CERT_DIR = Path(os.environ.get("ZT_CERT_DIR", "/etc/zt-thesis/certs"))
LOG_DIR  = Path(os.environ.get("ZT_LOG_DIR",  "/var/log/zt-thesis"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

LISTEN_HOST     = "0.0.0.0"
LISTEN_PORT     = 8443
DENY_THRESHOLD  = 60                         # score >= 60 -> DENY
SESSION_TTL_S   = 120                        # session lifetime in seconds
REAPER_INT_S    = 30                         # reaper poll interval
TIMESTAMP_SKEW  = 5                          # accept telemetry within ±5s

SUPPORTED_SCOPES = {"smb", "nfs", "sftp", "sql", "s3", "rest", "webdav"}
# Map scope 
SCOPE_TO_TARGET = {
    "smb":    ("192.168.30.0/24", [445]),
    "nfs":    ("192.168.30.0/24", [2049]),
    "sftp":   ("192.168.30.0/24", [22]),
    "sql":    ("192.168.30.0/24", [1433]),
    "s3":     ("192.168.40.0/24", [9000]),
    "rest":   ("192.168.40.0/24", [443]),
    "webdav": ("192.168.40.0/24", [443]),
}

# Logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "pdp.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("pdp")


PRIVACY  = PrivacyTransform(seed_file=Path(__file__).parent / ".hmac_seed")
# builds key-pair on demand
HE       = HERiskEngine()                  
PEP      = PEPManager(wg_iface="wg0")
METRICS  = MeasurementLogger(LOG_DIR)
   # session_id 
SESSIONS: dict[str, dict[str, Any]] = {}     
SESS_LK  = threading.Lock()

app = Flask(__name__)

# Risk scoring
def score_from_baseline(t: dict[str, Any]) -> int:
    score = 0
    # Zone -heaviest weight : public/unknown adds 30
    z = (t.get("zone") or "").lower()
    score += {"trusted": 0, "corporate": 0, "public": 30,
              "remote": 30, "unknown": 50}.get(z, 50)
    # Disk encryption
    if not t.get("disk_encrypted", False):
        score += 20
    # Patch age
    pa = int(t.get("patch_age_days", 999))
    if pa > 90:   score += 25
    elif pa > 30: score += 15
    # Domain join
    if not t.get("domain_joined", False):
        score += 10
    # Failed logins
    fl = int(t.get("failed_logins", 0))
    if fl > 10:  score += 25
    elif fl > 3: score += 15
    # Antivirus
    if not t.get("av_enabled", True):
        score += 10
    # Firewall
    if not t.get("fw_enabled", True):
        score += 10
    # OS supported
    if not t.get("os_supported", True):
        score += 15
    # Tamper indicators for boot integrity and secure boot
    if not t.get("secure_boot", True):
        score += 10
    if t.get("login_anomaly", False):
        score += 10
    # Time since last reboot per ms 
    if int(t.get("uptime_hours", 0)) > 24 * 30:
        score += 5
    return min(score, 100)


def score_from_claims(c: dict[str, Any]) -> int:
    score = 0
    score += {"low": 0, "medium": 30, "high": 50}.get(
        (c.get("zone_risk") or "").lower(), 50)
    if not c.get("posture_ok", False):    score += 25
    if c.get("login_anomaly", False):     score += 15
    if not c.get("patch_recent", False):  score += 15
    if not c.get("av_fw_ok", False):      score += 10
    if not c.get("secure_boot", True):    score += 10
    return min(score, 100)


def make_decision(score: int) -> str:
    return "DENY" if score >= DENY_THRESHOLD else "ALLOW"


def _check_timestamp(ts_iso: str | None) -> bool:
    if not ts_iso:
        return False
    try:
        ts = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
    except ValueError:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    now = datetime.now(tz=timezone.utc)
    return abs((now - ts).total_seconds()) <= TIMESTAMP_SKEW


def _validate_scope(scopes: list[str]) -> list[str]:
    return [s for s in scopes if s in SUPPORTED_SCOPES]

# Endpoints

@app.route("/api/v1/health", methods=["GET"])
def health():
    with SESS_LK:
        n = len(SESSIONS)
    return jsonify({
        "status":   "ok",
        "sessions": n,
        "services": sorted(SUPPORTED_SCOPES),
        "modes":    ["baseline", "hmac", "he"],
        "uptime_s": int(time.time() - START_TS),
    })


@app.route("/api/v1/salt", methods=["GET"])
def get_salt():
    """Return current daily HMAC salt hash for verification."""
    return jsonify({"salt_hash": PRIVACY.current_salt_hash(),
                    "rotated_at": PRIVACY.rotated_at_iso()})


@app.route("/api/v1/telemetry", methods=["POST"])
def telemetry():
    """
    Accepts telemetry in three modes (baseline, hmac, he), returns ALLOW/DENY decision and enforces via PEP.
    """
    t0 = time.perf_counter()
    body = request.get_json(silent=True) or {}
    mode = (body.get("mode") or "").lower()
    if mode not in ("baseline", "hmac", "he"):
        return jsonify({"error": "invalid mode"}), 400

    if not _check_timestamp(body.get("timestamp")):
        return jsonify({"error": "timestamp out of window"}), 400

    scopes = _validate_scope(body.get("requested_resources") or [])
    if not scopes:
        return jsonify({"error": "no valid scopes"}), 400

    tunnel_ip  = body.get("tunnel_ip")
    wg_pubkey  = body.get("wg_pubkey")
    if not tunnel_ip or not wg_pubkey:
        return jsonify({"error": "missing tunnel_ip or wg_pubkey"}), 400

    #  Mode-specific scoring
    if mode == "baseline":
        telemetry_obj = body.get("telemetry") or {}
        if PRIVACY.contains_identifier(telemetry_obj):
            pass
        score = score_from_baseline(telemetry_obj)
        diag_record = {"telemetry": telemetry_obj}

    elif mode == "hmac":
        claims = body.get("claims") or {}
        if PRIVACY.contains_identifier(claims):
            METRICS.log_rejection(mode, "identifier_present", body)
            return jsonify({"error": "identifier present in claims"}), 400
        score = score_from_claims(claims)
        diag_record = {"claims": claims}

    else: 
        enc_zone    = body.get("enc_zone")
        enc_posture = body.get("enc_posture")
        enc_login   = body.get("enc_login")
        pub_n       = body.get("pub_key_n")
        if not all([enc_zone, enc_posture, enc_login, pub_n]):
            return jsonify({"error": "missing encrypted fields"}), 400
        score = HE.evaluate(enc_zone, enc_posture, enc_login, pub_n)
        diag_record = {"he_pub_n_bits": len(bin(int(pub_n))) - 2}

    action = make_decision(score)

    #Session establishment
    session_id = body.get("session_id") or f"sess-{int(time.time()*1000)}-{os.urandom(3).hex()}"
    now = time.time()
    with SESS_LK:
        SESSIONS[session_id] = {
            "session_id":  session_id,
            "tunnel_ip":   tunnel_ip,
            "wg_pubkey":   wg_pubkey,
            "scopes":      scopes,
            "mode":        mode,
            "last_seen":   now,
            "expires":     now + SESSION_TTL_S,
            "action":      action,
            "score":       score,
        }

    #Enforcement
    if action == "ALLOW":
        PEP.enforce_allow(tunnel_ip, wg_pubkey, scopes, SCOPE_TO_TARGET)
    else:
        PEP.enforce_deny(tunnel_ip, wg_pubkey, scopes, SCOPE_TO_TARGET)
        with SESS_LK:
            SESSIONS.pop(session_id, None)

    #  Measurement 
    latency_ms = (time.perf_counter() - t0) * 1000.0
    METRICS.log_decision({
        "ts":         datetime.now(tz=timezone.utc).isoformat(),
        "mode":       mode,
        "action":     action,
        "score":      score,
        "scope":      ",".join(scopes),
        "tunnel_ip":  tunnel_ip,
        "session_id": session_id,
        "latency_ms": round(latency_ms, 3),
        **diag_record,
    })

    return jsonify({
        "action":     action,
        "score":      score,
        "session_id": session_id,
        "ttl_s":      SESSION_TTL_S,
        "mode":       mode,
    })

# client encrypts threshold T (=60), PDP returns
    Enc(score - T). Client decrypts and reads sign bit
   
@app.route("/api/v1/he_finalise", methods=["POST"])
def he_finalise():
  
    body = request.get_json(silent=True) or {}
    enc_score = body.get("enc_score")
    enc_thresh = body.get("enc_threshold")
    pub_n = body.get("pub_key_n")
    if not all([enc_score, enc_thresh, pub_n]):
        return jsonify({"error": "missing fields"}), 400
    diff = HE.subtract(enc_score, enc_thresh, pub_n)
    return jsonify({"enc_diff": diff})


@app.route("/api/v1/revoke", methods=["POST"])
def revoke():
    body = request.get_json(silent=True) or {}
    sid = body.get("session_id")
    if not sid:
        return jsonify({"error": "session_id required"}), 400
    with SESS_LK:
        s = SESSIONS.pop(sid, None)
    if s:
        PEP.enforce_deny(s["tunnel_ip"], s["wg_pubkey"],
                         s["scopes"], SCOPE_TO_TARGET)
        METRICS.log_decision({
            "ts":     datetime.now(tz=timezone.utc).isoformat(),
            "mode":   s["mode"],
            "action": "REVOKE",
            "score":  s["score"],
            "scope":  ",".join(s["scopes"]),
            "tunnel_ip":  s["tunnel_ip"],
            "session_id": sid,
            "latency_ms": 0.0,
        })
    return jsonify({"revoked": bool(s)})

#Read-only diagnostic it counts only, no PII
@app.route("/api/v1/sessions", methods=["GET"])
def list_sessions():
    with SESS_LK:
        return jsonify({
            "active": len(SESSIONS),
            "by_mode": {
                m: sum(1 for s in SESSIONS.values() if s["mode"] == m)
                for m in ("baseline", "hmac", "he")
            },
        })


@app.route("/api/v1/metrics", methods=["GET"])
def metrics():
    """Prometheus exposition format."""
    return METRICS.prometheus(), 200, {"Content-Type": "text/plain; version=0.0.4"}

# Session reaper
def _reaper():
    log.info("session reaper started (interval=%ds, ttl=%ds)",
             REAPER_INT_S, SESSION_TTL_S)
    while True:
        time.sleep(REAPER_INT_S)
        now = time.time()
        expired = []
        with SESS_LK:
            for sid, s in list(SESSIONS.items()):
                if s["expires"] <= now:
                    expired.append(s)
                    SESSIONS.pop(sid, None)
        for s in expired:
            log.info("reaping session %s (mode=%s, ip=%s)",
                     s["session_id"], s["mode"], s["tunnel_ip"])
            try:
                PEP.enforce_deny(s["tunnel_ip"], s["wg_pubkey"],
                                 s["scopes"], SCOPE_TO_TARGET)
                METRICS.log_decision({
                    "ts":     datetime.now(tz=timezone.utc).isoformat(),
                    "mode":   s["mode"],
                    "action": "EXPIRE",
                    "score":  s["score"],
                    "scope":  ",".join(s["scopes"]),
                    "tunnel_ip":  s["tunnel_ip"],
                    "session_id": s["session_id"],
                    "latency_ms": 0.0,
                })
            except Exception as e:
                log.exception("reaper enforcement failed: %s", e)

# Entry point - TLS context with client-cert request

START_TS = time.time()

def _make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT_DIR / "pdp.crt"),
                        keyfile=str(CERT_DIR / "pdp.key"))
    ctx.load_verify_locations(cafile=str(CERT_DIR / "ca.crt"))
    ctx.verify_mode = ssl.CERT_REQUIRED  
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def main():
    threading.Thread(target=_reaper, daemon=True).start()
    ssl_ctx = _make_ssl_context()
    log.info("PDP listening on https://%s:%d (mTLS)", LISTEN_HOST, LISTEN_PORT)
    app.run(host=LISTEN_HOST, port=LISTEN_PORT,
            ssl_context=ssl_ctx, threaded=True, debug=False)


if __name__ == "__main__":
    main()
