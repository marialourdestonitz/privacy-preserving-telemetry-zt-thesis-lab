#!/usr/bin/env python3

import asyncio
import logging
import os
import ssl
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import ipaddress

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, field_validator, model_validator

# the helper modules sit next to this file
sys.path.insert(0, str(Path(__file__).resolve().parent))
import scoring
from privacy_transform import PrivacyTransform
from he_risk_engine import HERiskEngine
from pep_manager import PEPManager
from measurement import MeasurementLogger

# config 
CERT_DIR = Path(os.environ.get("ZT_CERT_DIR", "/etc/zt-thesis/certs"))
LOG_DIR  = Path(os.environ.get("ZT_LOG_DIR",  "/var/log/zt-thesis"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

LISTEN_HOST    = "0.0.0.0"
LISTEN_PORT    = 8443
DENY_THRESHOLD = scoring.THRESHOLD 
SESSION_TTL_S  = 120
REAPER_INT_S   = 30
TIMESTAMP_SKEW = 30    


SUPPORTED_SCOPES = {"smb", "s3"}

SCOPE_TO_TARGET = {
    "smb": ("192.168.30.0/24", [445]),
    "s3":  ("192.168.40.0/24", [9000, 9001]),
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler(LOG_DIR / "pdp.log"), logging.StreamHandler()],
)
log = logging.getLogger("pdp")

# 
PRIVACY  = PrivacyTransform()
HE       = HERiskEngine()
PEP      = PEPManager(wg_iface=os.environ.get("ZT_WG_IFACE", "wg0"))
METRICS  = MeasurementLogger(LOG_DIR)
SESSIONS: dict[str, dict[str, Any]] = {}
SESS_LK  = asyncio.Lock()
START_TS = time.time()


NONCES: dict[str, float] = {}
NONCE_LK = asyncio.Lock()
NONCE_TTL_S = 2 * TIMESTAMP_SKEW


# request and response
ModeLiteral = Literal["baseline", "hmac", "he"]



class BaselineTelemetry(BaseModel):
    # full posture
    hostname:       str | None = None
    username:       str | None = None
    mac_address:    str | None = None
    ip_address:     str | None = None
    sid:            str | None = None
    zone:           Literal["trusted","corporate","public","remote","unknown"] | None = None
    disk_encrypted: bool | None = None
    patch_age_days: int  | None = None
    domain_joined:  bool | None = None
    failed_logins:  int  | None = None
    av_enabled:     bool | None = None
    fw_enabled:     bool | None = None
    os_supported:   bool | None = None
    secure_boot:    bool | None = None
    login_anomaly:  bool | None = None
    uptime_hours:   int  | None = None

    model_config = {"extra": "allow"}


class HMACClaims(BaseModel):
    # Minimised + pseudonymised. extra=forbid so a raw hostname etc. can't
    # sneak in at the top level.
    #
    # REVIEW FIX (Finding A): the claims now carry the SAME factor set as the
    # canonical scorer, as bands and booleans. Minimisation removes identifiers
    # and granular values (exact patch age -> band, exact login count -> band),
    # not scoring factors — that is what makes exact cross-mode parity possible.
    device_id_hmac: str = Field(..., min_length=16, max_length=64)
    zone_risk:      Literal["low", "medium", "high"]
    disk_ok:        bool
    patch_band:     Literal["recent", "stale", "very_stale"]
    domain_ok:      bool
    login_band:     Literal["none", "some", "many"]
    av_ok:          bool
    fw_ok:          bool
    os_ok:          bool
    secure_boot:    bool
    login_anomaly:  bool
    uptime_ok:      bool

    model_config = {"extra": "forbid"}


class TelemetryRequest(BaseModel):
    mode:                ModeLiteral
    timestamp:           datetime
    tunnel_ip:           str
    wg_pubkey:           str = Field(..., min_length=10)
    requested_resources: list[str] = Field(..., min_length=1)
    session_id:          str | None = None
    nonce:               str | None = Field(None, min_length=8, max_length=64)

    # one of these blocks gets filled depending on mode
    telemetry:   BaselineTelemetry | None = None
    claims:      HMACClaims        | None = None
    # HE mode: the four encrypted sub-scores (engine-serialised strings) + key.
    enc_zone:    str | None = None
    enc_posture: str | None = None
    enc_patch:   str | None = None
    enc_login:   str | None = None
    pub_key_n:   str | None = None

    @field_validator("timestamp")
    @classmethod
    def fresh_timestamp(cls, v: datetime) -> datetime:
        # reject stale/replayed telemetry
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        skew = abs((datetime.now(tz=timezone.utc) - v).total_seconds())
        if skew > TIMESTAMP_SKEW:
            raise ValueError(f"timestamp out of window (skew={skew:.1f}s)")
        return v

    @field_validator("tunnel_ip")
    @classmethod
    def valid_ip(cls, v: str) -> str:
        ipaddress.ip_address(v)  # throws if it's not an IP
        return v

    @field_validator("requested_resources")
    @classmethod
    def valid_scopes(cls, v: list[str]) -> list[str]:
        valid = [s for s in v if s in SUPPORTED_SCOPES]
        if not valid:
            raise ValueError(f"no valid scopes (got {v})")
        return valid

    @model_validator(mode="after")
    def mode_payload_consistency(self):
        # make sure the block matching the mode is actually present
        if self.mode == "baseline" and self.telemetry is None:
            raise ValueError("baseline mode needs 'telemetry'")
        if self.mode == "hmac" and self.claims is None:
            raise ValueError("hmac mode needs 'claims'")
        if self.mode == "he":
            if not all([self.enc_zone, self.enc_posture, self.enc_patch,
                        self.enc_login, self.pub_key_n]):
                raise ValueError("he mode needs enc_zone/enc_posture/enc_patch/"
                                 "enc_login + pub_key_n")
        return self


class HEDecisionRequest(BaseModel):
    # In HE mode the PDP returns Enc(score - threshold) and never learns the
    # score. The client decrypts the sign locally (he_decrypt.py) and reports
    # the resulting verdict here so the PEP can enforce it.
    #
    # DESIGN DECISION (confirm with supervisor): this trusts the client's
    # self-reported HE verdict. That is consistent with the threat model's
    # stated out-of-scope item ("malicious client deliberately reporting false
    # good posture ... full posture attestation is future work").
    #
    # REVIEW FIX: tunnel_ip is now required and must match the pending
    # session, so one authenticated client cannot answer for another's
    # pending HE session by guessing session ids.
    session_id: str = Field(..., min_length=1)
    tunnel_ip:  str
    action:     Literal["ALLOW", "DENY"]

    @field_validator("tunnel_ip")
    @classmethod
    def valid_ip(cls, v: str) -> str:
        ipaddress.ip_address(v)
        return v


class RevokeRequest(BaseModel):
    session_id: str = Field(..., min_length=1)


# --- scoring (delegated to scoring.py — Finding A) ---------------------------
def make_decision(score: int) -> str:
    return scoring.decision(score)


# --- replay-nonce check -------------------------------------------------------
async def _check_nonce(nonce: str | None, mode: str) -> None:
    if nonce is None:
        log.debug("telemetry without nonce (mode=%s) — allowed, but the "
                  "agent should send one", mode)
        return
    now = time.time()
    async with NONCE_LK:
        if nonce in NONCES:
            METRICS.log_rejection(mode, "nonce_replayed", {"nonce": nonce})
            raise HTTPException(400, "nonce replayed")
        NONCES[nonce] = now


# --- session helpers -----------------------------------------------------------
def _new_session_id() -> str:
    return f"sess-{int(time.time()*1000)}-{os.urandom(8).hex()}"


async def _resolve_session_id(requested: str | None, tunnel_ip: str,
                              mode: str) -> str:
    """A client may continue its own session, but a session_id bound to a
    different tunnel_ip cannot be reused/overwritten (review fix)."""
    if not requested:
        return _new_session_id()
    async with SESS_LK:
        existing = SESSIONS.get(requested)
    if existing and existing["tunnel_ip"] != tunnel_ip:
        METRICS.log_rejection(mode, "session_ip_mismatch",
                              {"session_id": requested, "tunnel_ip": tunnel_ip})
        raise HTTPException(403, "session_id belongs to a different client")
    return requested


# --- session reaper --------------------------------------------------------
async def _reaper() -> None:
    # kills expired sessions and tears down their access. worst case a session
    # outlives its TTL by one sweep interval (~30s). NOTE for the evaluation
    # (Finding I): this bound is the EXPIRY-revocation latency and must be
    # reported separately from per-request decision latency.
    log.info("reaper up (every %ds, ttl %ds)", REAPER_INT_S, SESSION_TTL_S)
    while True:
        await asyncio.sleep(REAPER_INT_S)
        now = time.time()
        expired = []
        async with SESS_LK:
            for sid, s in list(SESSIONS.items()):
                if s["expires"] <= now:
                    expired.append(s)
                    SESSIONS.pop(sid, None)
        # prune stale nonces while we're here
        async with NONCE_LK:
            for n, ts in list(NONCES.items()):
                if now - ts > NONCE_TTL_S:
                    NONCES.pop(n, None)
        # do the actual revoke outside the lock; enforce_deny shells out so
        # push it to the executor
        loop = asyncio.get_event_loop()
        for s in expired:
            log.info("reaping %s (mode=%s ip=%s)", s["session_id"], s["mode"], s["tunnel_ip"])
            try:
                # Two distinct quantities, both needed by Chapter 7 and
                # previously neither recorded (latency_ms was hardcoded 0.0,
                # so the expiry series on the dashboard was meaningless):
                #
                #   teardown_ms  how long enforce_deny took to withdraw access
                #                across the three planes. This is the PDP-side
                #                cost of an expiry revocation.
                #   overdue_s    how long the session outlived its own expiry
                #                before the reaper swept it. This is the part
                #                of the ~150 s worst-case bound that is due to
                #                the sweep interval rather than the TTL, and it
                #                is what makes the bound an observed figure
                #                rather than an arithmetic claim.
                #
                # Note for Section 7.4: neither is the revocation time the
                # thesis reports. That is measured at the resource, because the
                # question is when access actually ends, not when the PDP
                # finished recording that it should.
                t_reap = time.perf_counter()
                await loop.run_in_executor(
                    None, PEP.enforce_deny,
                    s["tunnel_ip"], s["wg_pubkey"], s["scopes"], SCOPE_TO_TARGET,
                )
                teardown_ms = (time.perf_counter() - t_reap) * 1000.0
                METRICS.log_decision({
                    "ts": datetime.now(tz=timezone.utc).isoformat(),
                    "mode": s["mode"], "action": "EXPIRE", "score": s["score"],
                    "scope": ",".join(s["scopes"]), "tunnel_ip": s["tunnel_ip"],
                    "session_id": s["session_id"],
                    "latency_ms": round(teardown_ms, 3),
                    "overdue_s": round(now - s["expires"], 3),
                    "session_ttl_s": SESSION_TTL_S,
                    "phase": "expiry",
                })
            except Exception as e:
                log.exception("reaper revoke failed: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # start the reaper on boot, cancel it cleanly on shutdown
    reaper_task = asyncio.create_task(_reaper())
    yield
    reaper_task.cancel()
    try:
        await reaper_task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="ZT Policy Decision Point",
    description="Privacy-preserving telemetry / continuous verification (NIST 800-207).",
    version="1.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)


# --- endpoints -------------------------------------------------------------
@app.get("/api/v1/health")
async def health():
    async with SESS_LK:
        n = len(SESSIONS)
    return {
        "status": "ok", "sessions": n,
        "services": sorted(SUPPORTED_SCOPES),
        "modes": ["baseline", "hmac", "he"],
        "uptime_s": int(time.time() - START_TS),
    }


@app.get("/api/v1/salt")
async def get_salt():
    # expose the salt fingerprint so clients can check they're in sync,
    # without ever handing out the salt itself
    return {
        "salt_hash":  PRIVACY.get_current_salt_hash(),
        "rotated_at": PRIVACY.salt_expires_at().isoformat(),
    }


@app.get("/api/v1/salt/material")
async def get_salt_material():
    # REVIEW FIX (Finding D): hand the actual rotating salt to authenticated
    # clients so device_id_hmac becomes a keyed pseudonym. This endpoint is
    # reachable only over the server's mTLS listener — an unauthenticated
    # party never sees it. THREAT-MODEL NOTE (document in Chapter 8): every
    # enrolled client learns the same salt, so the pseudonym is keyed against
    # outsiders and against the log/telemetry plane, not against a malicious
    # sibling client; per-client keys would be the stricter alternative.
    return {
        "salt":       PRIVACY.get_salt_material(),
        "salt_hash":  PRIVACY.get_current_salt_hash(),
        "rotated_at": PRIVACY.salt_expires_at().isoformat(),
    }


@app.post("/api/v1/telemetry")
async def telemetry(req: TelemetryRequest):
    # by the time we're here Pydantic has already validated mode, timestamp,
    # ip, scopes and the right sub-block. so just score + enforce + log.
    t0 = time.perf_counter()
    loop = asyncio.get_event_loop()

    await _check_nonce(req.nonce, req.mode)

    # ----- HE mode: privacy-preserving, two-round ----------------------------
    # The PDP homomorphically computes Enc(score - threshold) and returns it
    # WITHOUT ever decrypting. It does not learn the score or the decision here
    # and does NOT enforce yet. The client decrypts the sign locally
    # (he_decrypt.py) and reports its verdict to /api/v1/he_decision, which then
    # drives the PEP. A pending session is parked so the follow-up can find it.
    if req.mode == "he":
        he_out = await loop.run_in_executor(
            None, HE.evaluate_encrypted,
            {
                "enc_zone":    req.enc_zone,
                "enc_posture": req.enc_posture,
                "enc_patch":   req.enc_patch,
                "enc_login":   req.enc_login,
                "pub_key_n":   req.pub_key_n,
            },
        )
        he_session = await _resolve_session_id(req.session_id, req.tunnel_ip, "he")
        now = time.time()
        async with SESS_LK:
            SESSIONS[he_session] = {
                "session_id": he_session, "tunnel_ip": req.tunnel_ip,
                "wg_pubkey": req.wg_pubkey, "scopes": req.requested_resources,
                "mode": "he", "last_seen": now, "expires": now + SESSION_TTL_S,
                "action": "PENDING_HE", "score": None,
            }
        he_latency_ms = (time.perf_counter() - t0) * 1000.0
        METRICS.log_decision({
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "mode": "he", "action": "EVAL", "score": None,
            "scope": ",".join(req.requested_resources),
            "tunnel_ip": req.tunnel_ip, "session_id": he_session,
            "latency_ms": round(he_latency_ms, 3),
            "he_eval_ms": he_out.get("he_eval_ms"),
            "he_pub_n_bits": len(bin(int(req.pub_key_n))) - 2,
            "phase": "he_round1",   # Finding L: phase-tagged latencies
        })
        # encrypted comparison only — no action, no score leaves the PDP
        return {
            "mode": "he", "session_id": he_session, "ttl_s": SESSION_TTL_S,
            "enc_comparison": he_out["enc_comparison"], "pub_key_n": req.pub_key_n,
        }

    # ----- baseline / hmac: PDP scores and enforces directly -----------------
    diag_record: dict[str, Any]
    if req.mode == "baseline":
        tel_dict = req.telemetry.model_dump(exclude_none=True)
        # baseline keeps identifiers on purpose, so we don't reject here
        score = scoring.score_from_posture(tel_dict)      # Finding A
        diag_record = {"telemetry": tel_dict}

    elif req.mode == "hmac":
        claims_dict = req.claims.model_dump(exclude_none=True)
        # second line of defence on top of extra=forbid: walk the dict and
        # bounce it if any raw identifier slipped through nested
        if PRIVACY.contains_identifier(claims_dict):
            METRICS.log_rejection("hmac", "identifier_present", req.model_dump())
            raise HTTPException(400, "identifier present in claims")
        score = scoring.score_from_claims(claims_dict)    # Finding A
        diag_record = {"claims": claims_dict}

    else:  # unreachable: HE is handled and returned above
        raise HTTPException(400, f"unsupported mode {req.mode!r}")

    action = make_decision(score)

    session_id = await _resolve_session_id(req.session_id, req.tunnel_ip, req.mode)
    now = time.time()
    async with SESS_LK:
        SESSIONS[session_id] = {
            "session_id": session_id, "tunnel_ip": req.tunnel_ip,
            "wg_pubkey": req.wg_pubkey, "scopes": req.requested_resources,
            "mode": req.mode, "last_seen": now, "expires": now + SESSION_TTL_S,
            "action": action, "score": score,
        }

    # enforce_allow/deny shell out to wg + iptables, so executor again
    cloud_creds = None
    if action == "ALLOW":
        await loop.run_in_executor(
            None, PEP.enforce_allow,
            req.tunnel_ip, req.wg_pubkey, req.requested_resources, SCOPE_TO_TARGET,
        )
        # per-session cloud credentials (now random per issue — review fix E);
        # delivered over this mTLS channel only.
        cloud_creds = PEP.get_cloud_credentials(req.tunnel_ip)
    else:
        await loop.run_in_executor(
            None, PEP.enforce_deny,
            req.tunnel_ip, req.wg_pubkey, req.requested_resources, SCOPE_TO_TARGET,
        )
        async with SESS_LK:
            SESSIONS.pop(session_id, None)

    latency_ms = (time.perf_counter() - t0) * 1000.0
    METRICS.log_decision({
        "ts": datetime.now(tz=timezone.utc).isoformat(),
        "mode": req.mode, "action": action, "score": score,
        "scope": ",".join(req.requested_resources),
        "tunnel_ip": req.tunnel_ip, "session_id": session_id,
        "latency_ms": round(latency_ms, 3),
        "phase": "decision",
        **diag_record,
    })

    resp = {
        "action": action, "score": score, "session_id": session_id,
        "ttl_s": SESSION_TTL_S, "mode": req.mode,
    }
    if cloud_creds:
        resp["cloud_credentials"] = cloud_creds
    return resp


@app.post("/api/v1/he_decision")
async def he_decision(req: HEDecisionRequest):
    # The client has decrypted Enc(score - threshold) locally and reports its
    # verdict; the PEP enforces it. The PDP still never sees the score. See the
    # HEDecisionRequest docstring for the trust-assumption design note.
    loop = asyncio.get_event_loop()
    async with SESS_LK:
        s = SESSIONS.get(req.session_id)
    if not s or s.get("mode") != "he":
        raise HTTPException(404, "no pending HE session for that id")
    if s["tunnel_ip"] != req.tunnel_ip:
        # review fix: a session can only be answered by the client it belongs to
        METRICS.log_rejection("he", "he_decision_ip_mismatch",
                              {"session_id": req.session_id,
                               "tunnel_ip": req.tunnel_ip})
        raise HTTPException(403, "session belongs to a different client")

    t0 = time.perf_counter()
    cloud_creds = None
    if req.action == "ALLOW":
        async with SESS_LK:
            s["action"] = "ALLOW"
        await loop.run_in_executor(
            None, PEP.enforce_allow,
            s["tunnel_ip"], s["wg_pubkey"], s["scopes"], SCOPE_TO_TARGET,
        )
        cloud_creds = PEP.get_cloud_credentials(s["tunnel_ip"])
    else:
        await loop.run_in_executor(
            None, PEP.enforce_deny,
            s["tunnel_ip"], s["wg_pubkey"], s["scopes"], SCOPE_TO_TARGET,
        )
        async with SESS_LK:
            SESSIONS.pop(req.session_id, None)

    latency_ms = (time.perf_counter() - t0) * 1000.0
    METRICS.log_decision({
        "ts": datetime.now(tz=timezone.utc).isoformat(),
        "mode": "he", "action": req.action, "score": None,
        "scope": ",".join(s["scopes"]), "tunnel_ip": s["tunnel_ip"],
        "session_id": req.session_id, "latency_ms": round(latency_ms, 3),
        "phase": "he_round2",   # Finding L
    })
    resp = {"enforced": req.action, "session_id": req.session_id}
    if cloud_creds:
        resp["cloud_credentials"] = cloud_creds
    return resp


@app.post("/api/v1/revoke")
async def revoke(req: RevokeRequest):
    # manual revoke (used by the Explicit Revocation scenario, Scenario 5)
    t0 = time.perf_counter()
    loop = asyncio.get_event_loop()
    async with SESS_LK:
        s = SESSIONS.pop(req.session_id, None)
    if s:
        await loop.run_in_executor(
            None, PEP.enforce_deny,
            s["tunnel_ip"], s["wg_pubkey"], s["scopes"], SCOPE_TO_TARGET,
        )
        METRICS.log_decision({
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "mode": s["mode"], "action": "REVOKE", "score": s["score"],
            "scope": ",".join(s["scopes"]), "tunnel_ip": s["tunnel_ip"],
            "session_id": req.session_id,
            "latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            "phase": "revoke",   # Finding I: explicit-revocation latency
        })
    return {"revoked": bool(s)}


@app.get("/api/v1/sessions")
async def list_sessions():
    # counts only, no PII — safe to expose to the dashboard
    async with SESS_LK:
        return {
            "active": len(SESSIONS),
            "by_mode": {m: sum(1 for s in SESSIONS.values() if s["mode"] == m)
                        for m in ("baseline", "hmac", "he")},
        }


@app.get("/api/v1/metrics")
async def metrics():
    return PlainTextResponse(
        content=METRICS.prometheus(),
        media_type="text/plain; version=0.0.4",
    )


# keep the error shape as {"error": "..."} so the existing client agent
# doesn't need changing (FastAPI defaults to {"detail": ...})
from fastapi.exceptions import RequestValidationError

@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    reason = exc.errors()[0].get("msg", "validation error") if exc.errors() else "validation error"
    try:
        body = await request.json()
    except Exception:
        body = {}
    mode = body.get("mode", "?") if isinstance(body, dict) else "?"
    METRICS.log_rejection(mode, reason, body if isinstance(body, dict) else {})
    return JSONResponse(status_code=400, content={"error": reason})


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


# --- entrypoint ------------------------------------------------------------
def main():
    log.info("PDP up on https://%s:%d (mTLS)", LISTEN_HOST, LISTEN_PORT)
    uvicorn.run(
        "pdp_server:app",
        host=LISTEN_HOST, port=LISTEN_PORT,
        ssl_keyfile=str(CERT_DIR / "pdp.key"),
        ssl_certfile=str(CERT_DIR / "pdp.crt"),
        ssl_ca_certs=str(CERT_DIR / "ca.crt"),
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        ssl_version=ssl.PROTOCOL_TLS_SERVER,
        log_config=None, access_log=False,
        workers=1,   # Finding C: MUST stay 1 — SESSIONS is in-process state
    )


if __name__ == "__main__":
    main()
