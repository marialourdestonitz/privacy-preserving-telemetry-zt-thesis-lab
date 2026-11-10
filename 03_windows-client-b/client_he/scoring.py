#!/usr/bin/env python3
"""
scoring.py — the single source of truth for the trust algorithm.

REVIEW FIX (Finding A, implementation review 2026-07):
Previously each telemetry mode had its own scoring function with its own
weights and its own subset of factors (baseline: 11 factors; hmac: 6 collapsed
claims; he: 4 factors). Near the threshold the three modes could disagree, so
a cross-mode decision difference could not be attributed to the privacy
mechanism — the independent variable was confounded.

This module now defines the canonical factor set, weights, and threshold ONCE.
Every mode consumes it:

  baseline  ->  score_from_posture(raw)             (cleartext, all factors)
  hmac      ->  score_from_claims(claims)           (minimised claims: bands
                and booleans, no identifiers — same arithmetic)
  he        ->  subscores_from_posture(raw) gives the four sub-scores whose
                Paillier ciphertexts the client sends; their sum equals
                score_from_posture(raw) exactly.

The privacy transform changes only HOW the inputs reach the scorer
(cleartext, pseudonymised claim, ciphertext) — never the arithmetic.
test_scoring_parity.py asserts this equality over randomized posture vectors.

Design notes:
  * The old min(score, 100) cap is REMOVED: an additive cap cannot be applied
    homomorphically, and it never changes a decision (threshold 60 < cap).
    Scores are unbounded above; the decision rule is unchanged.
  * This file must be byte-identical on the PDP and on the client (the agent
    installer copies it next to he_encrypt.py). The PowerShell agent mirrors
    CLAIM-band logic in Build-HmacClaims; keep them in sync.
"""
from __future__ import annotations

from typing import Any

# --- canonical parameters ---------------------------------------------------
THRESHOLD = 60          # score >= THRESHOLD -> DENY

ZONE_SCORES = {"trusted": 0, "corporate": 0, "public": 30, "remote": 30,
               "unknown": 50}
ZONE_DEFAULT = 50       # unrecognised zone counts as unknown

WEIGHTS = {
    "disk_not_encrypted": 20,
    "patch_stale":        15,   # patch_age_days  > 30
    "patch_very_stale":   25,   # patch_age_days  > 90
    "not_domain_joined":  10,
    "logins_some":        15,   # failed_logins   > 3
    "logins_many":        25,   # failed_logins   > 10
    "av_disabled":        10,
    "fw_disabled":        10,
    "os_unsupported":     15,
    "no_secure_boot":     10,
    "login_anomaly":      10,
    "uptime_excessive":    5,   # uptime_hours    > 720 (30 days)
}

PATCH_STALE_DAYS      = 30
PATCH_VERY_STALE_DAYS = 90
LOGINS_SOME           = 3
LOGINS_MANY           = 10
UPTIME_LIMIT_HOURS    = 720


# --- factor scorers ----------------------------------------------------------
def zone_score(zone: str | None) -> int:
    return ZONE_SCORES.get((zone or "unknown").lower(), ZONE_DEFAULT)


def patch_score(patch_age_days: int) -> int:
    if patch_age_days > PATCH_VERY_STALE_DAYS:
        return WEIGHTS["patch_very_stale"]
    if patch_age_days > PATCH_STALE_DAYS:
        return WEIGHTS["patch_stale"]
    return 0


def login_score(failed_logins: int, login_anomaly: bool) -> int:
    s = 0
    if failed_logins > LOGINS_MANY:
        s += WEIGHTS["logins_many"]
    elif failed_logins > LOGINS_SOME:
        s += WEIGHTS["logins_some"]
    if login_anomaly:
        s += WEIGHTS["login_anomaly"]
    return s


def posture_group_score(t: dict[str, Any]) -> int:
    """Everything that is neither zone, patch, nor login — the HE 'enc_posture'
    group: disk, domain, AV, firewall, OS support, secure boot, uptime."""
    s = 0
    if not t.get("disk_encrypted", False):
        s += WEIGHTS["disk_not_encrypted"]
    if not t.get("domain_joined", False):
        s += WEIGHTS["not_domain_joined"]
    if not t.get("av_enabled", True):
        s += WEIGHTS["av_disabled"]
    if not t.get("fw_enabled", True):
        s += WEIGHTS["fw_disabled"]
    if not t.get("os_supported", True):
        s += WEIGHTS["os_unsupported"]
    if not t.get("secure_boot", True):
        s += WEIGHTS["no_secure_boot"]
    if int(t.get("uptime_hours", 0)) > UPTIME_LIMIT_HOURS:
        s += WEIGHTS["uptime_excessive"]
    return s


# --- mode entry points --------------------------------------------------------
def subscores_from_posture(t: dict[str, Any]) -> dict[str, int]:
    """The four sub-scores carried by the HE wire fields. Their sum is the
    canonical score. The client encrypts each under its own Paillier key."""
    return {
        "zone":    zone_score(t.get("zone")),
        "posture": posture_group_score(t),
        "patch":   patch_score(int(t.get("patch_age_days", 999))),
        "login":   login_score(int(t.get("failed_logins", 0)),
                               bool(t.get("login_anomaly", False))),
    }


def score_from_posture(t: dict[str, Any]) -> int:
    """Canonical score over raw posture (baseline mode)."""
    return sum(subscores_from_posture(t).values())


# --- hmac mode: minimised claims -----------------------------------------------
# The claims carry the SAME factor set as bands/booleans — minimisation removes
# identifiers and granular values (exact patch age -> band, exact login count
# -> band), not scoring factors. This is what makes exact parity possible.

ZONE_RISK_SCORES  = {"low": 0, "medium": 30, "high": 50}
PATCH_BAND_SCORES = {"recent": 0, "stale": WEIGHTS["patch_stale"],
                     "very_stale": WEIGHTS["patch_very_stale"]}
LOGIN_BAND_SCORES = {"none": 0, "some": WEIGHTS["logins_some"],
                     "many": WEIGHTS["logins_many"]}


def claims_from_posture(t: dict[str, Any]) -> dict[str, Any]:
    """Reference minimisation raw posture -> claims (mirrors the agent's
    Build-HmacClaims; used by tests and the experiment orchestrator).
    Does NOT include device_id_hmac — pseudonymisation needs the salt."""
    zs = zone_score(t.get("zone"))
    zone_risk = "low" if zs == 0 else ("medium" if zs == 30 else "high")
    pa = int(t.get("patch_age_days", 999))
    patch_band = ("very_stale" if pa > PATCH_VERY_STALE_DAYS
                  else "stale" if pa > PATCH_STALE_DAYS else "recent")
    fl = int(t.get("failed_logins", 0))
    login_band = ("many" if fl > LOGINS_MANY
                  else "some" if fl > LOGINS_SOME else "none")
    return {
        "zone_risk":     zone_risk,
        "disk_ok":       bool(t.get("disk_encrypted", False)),
        "patch_band":    patch_band,
        "domain_ok":     bool(t.get("domain_joined", False)),
        "login_band":    login_band,
        "av_ok":         bool(t.get("av_enabled", True)),
        "fw_ok":         bool(t.get("fw_enabled", True)),
        "os_ok":         bool(t.get("os_supported", True)),
        "secure_boot":   bool(t.get("secure_boot", True)),
        "login_anomaly": bool(t.get("login_anomaly", False)),
        "uptime_ok":     int(t.get("uptime_hours", 0)) <= UPTIME_LIMIT_HOURS,
    }


def score_from_claims(c: dict[str, Any]) -> int:
    """Canonical score over minimised claims (hmac mode). Same weights,
    same factors, same result as score_from_posture on the source posture."""
    s = ZONE_RISK_SCORES.get((c.get("zone_risk") or "").lower(), 50)
    if not c.get("disk_ok", False):
        s += WEIGHTS["disk_not_encrypted"]
    s += PATCH_BAND_SCORES.get((c.get("patch_band") or "very_stale").lower(),
                               WEIGHTS["patch_very_stale"])
    if not c.get("domain_ok", False):
        s += WEIGHTS["not_domain_joined"]
    s += LOGIN_BAND_SCORES.get((c.get("login_band") or "none").lower(), 0)
    if not c.get("av_ok", True):
        s += WEIGHTS["av_disabled"]
    if not c.get("fw_ok", True):
        s += WEIGHTS["fw_disabled"]
    if not c.get("os_ok", True):
        s += WEIGHTS["os_unsupported"]
    if not c.get("secure_boot", True):
        s += WEIGHTS["no_secure_boot"]
    if c.get("login_anomaly", False):
        s += WEIGHTS["login_anomaly"]
    if not c.get("uptime_ok", True):
        s += WEIGHTS["uptime_excessive"]
    return s


def decision(score: int) -> str:
    return "DENY" if score >= THRESHOLD else "ALLOW"
