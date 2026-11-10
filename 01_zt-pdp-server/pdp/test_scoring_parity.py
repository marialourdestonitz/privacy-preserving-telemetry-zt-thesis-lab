#!/usr/bin/env python3
"""
test_scoring_parity.py — cross-mode decision-equivalence test (Finding A).

Asserts, over exhaustive corner cases plus randomized posture vectors, that:

  1. baseline score  == sum of the four HE sub-scores       (exact)
  2. baseline score  == hmac score of the minimised claims  (exact)
  3. all three modes therefore yield the same ALLOW/DENY decision

Run:  python3 test_scoring_parity.py          (no dependencies, no phe needed)
      or: pytest test_scoring_parity.py

This test is what licenses the thesis claim that the three telemetry modes
differ only in privacy exposure, not in the access decision they produce.
"""
import random
import sys

import scoring


ZONES = ["trusted", "corporate", "public", "remote", "unknown", "weird-value"]


def random_posture(rng: random.Random) -> dict:
    return {
        "zone":           rng.choice(ZONES),
        "disk_encrypted": rng.random() < 0.5,
        "patch_age_days": rng.choice([0, 5, 29, 30, 31, 89, 90, 91, 400, 999]),
        "domain_joined":  rng.random() < 0.5,
        "failed_logins":  rng.choice([0, 1, 3, 4, 9, 10, 11, 50]),
        "av_enabled":     rng.random() < 0.5,
        "fw_enabled":     rng.random() < 0.5,
        "os_supported":   rng.random() < 0.5,
        "secure_boot":    rng.random() < 0.5,
        "login_anomaly":  rng.random() < 0.5,
        "uptime_hours":   rng.choice([0, 100, 719, 720, 721, 5000]),
    }


def corner_postures() -> list[dict]:
    best = {"zone": "trusted", "disk_encrypted": True, "patch_age_days": 0,
            "domain_joined": True, "failed_logins": 0, "av_enabled": True,
            "fw_enabled": True, "os_supported": True, "secure_boot": True,
            "login_anomaly": False, "uptime_hours": 1}
    worst = {"zone": "unknown", "disk_encrypted": False, "patch_age_days": 999,
             "domain_joined": False, "failed_logins": 50, "av_enabled": False,
             "fw_enabled": False, "os_supported": False, "secure_boot": False,
             "login_anomaly": True, "uptime_hours": 9999}
    # threshold-straddling case: exactly at the boundary bands
    edge = dict(best, zone="public", disk_encrypted=False,
                patch_age_days=31)          # 30 + 20 + 15 = 65 -> DENY
    edge_below = dict(best, zone="public", disk_encrypted=False)  # 50 -> ALLOW
    return [best, worst, edge, edge_below]


def check(t: dict) -> None:
    s_baseline = scoring.score_from_posture(t)
    subs       = scoring.subscores_from_posture(t)
    s_he       = sum(subs.values())
    claims     = scoring.claims_from_posture(t)
    s_hmac     = scoring.score_from_claims(claims)

    assert s_baseline == s_he, (
        f"HE sub-score sum {s_he} != baseline {s_baseline} for {t} (subs={subs})")
    assert s_baseline == s_hmac, (
        f"hmac score {s_hmac} != baseline {s_baseline} for {t} (claims={claims})")
    d = scoring.decision(s_baseline)
    assert d == scoring.decision(s_he) == scoring.decision(s_hmac)


def test_corner_cases():
    for t in corner_postures():
        check(t)


def test_known_decisions():
    best, worst, edge, edge_below = corner_postures()
    assert scoring.decision(scoring.score_from_posture(best)) == "ALLOW"
    assert scoring.decision(scoring.score_from_posture(worst)) == "DENY"
    assert scoring.decision(scoring.score_from_posture(edge)) == "DENY"
    assert scoring.decision(scoring.score_from_posture(edge_below)) == "ALLOW"


def test_randomized_sweep():
    rng = random.Random(42)   # fixed seed: reproducible
    for _ in range(20000):
        check(random_posture(rng))


if __name__ == "__main__":
    test_corner_cases()
    test_known_decisions()
    test_randomized_sweep()
    print("PARITY OK: baseline == hmac == he over 20,000 random postures "
          "+ corner cases (seed=42).")
    sys.exit(0)
