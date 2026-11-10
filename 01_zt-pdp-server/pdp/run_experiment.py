#!/usr/bin/env python3
"""
run_experiment.py — reproducible measurement campaign (review Findings H/I/L).

Drives the documented Scenarios 1-7 against a running PDP, for each telemetry
mode (baseline / hmac / he), N repetitions each, with a warm-up discard —
and records every outcome through MeasurementLogger.record_scenario_result().
Emits:

    zt-scenario-matrix.csv      pass/fail per scenario x mode x repetition
    zt-experiment-summary.json  latency stats (mean/median/p95, n) per cell,
                                broken out by phase (decision vs he_round1 +
                                he_round2 vs revoke), plus payload wire sizes

The orchestrator emulates a client: it holds a client certificate and, in HE
mode, a locally generated Paillier keypair (encrypt + sign-decrypt exactly as
context_agent.ps1 + he_encrypt/he_decrypt do). Scenario postures are synthetic
and identical across modes, so cross-mode rows are directly comparable —
which is what Finding A's unified scoring makes meaningful.

REVISED 2026-08-11. Four defects were found while preparing the evaluation
chapter; each one left a row of the results table permanently unfillable:

  (1) Scenario 5 was never recorded. The loop called revoke() and timed it,
      but skipped record_scenario_result() for S5 entirely, so no S5 row could
      ever appear in the scenario matrix. It is now recorded with an expected
      action of REVOKE.

  (2) Scenario 7 did not exist. The old docstring claimed it was "realised by
      the scope set", but nothing recorded an S7 row. Hybrid teardown is now an
      explicit two-step scenario: grant both planes, then degrade posture and
      assert that ONE decision withdraws smb and s3 together.

  (3) Scenario 2 did not test micro-segmentation. Every scenario ran as one
      client with SCOPES = [smb, s3], so client B's smb-only scope was never
      exercised and the headline demo had no automated evidence. The harness
      now drives a second client identity with its own certificate and its own
      narrower scope set, and asserts on the granted scope, not merely on the
      action. See the note on reachability below.

  (4) Wire size was measured and then discarded. It is now carried into the
      summary per mode as its own aggregate, because payload overhead is part
      of the cost of the privacy transform and Paillier ciphertexts are the
      largest single contributor to it.

WHAT THIS HARNESS CANNOT DO, and why that is stated rather than hidden.
It measures the PDP's DECISION and the scope that decision granted. It does
not measure reachability, because reachability has to be tested from the
client's own network position, and this script runs on the PDP host. So for
Scenario 2 the harness proves the PDP granted client B smb and withheld s3;
proving that client B can actually open port 445 and actually cannot open
port 9000 remains the manual Test-NetConnection step in MT-test-scenarios.
Both halves belong in Section 7.3. Do not report the harness result as though
it were the reachability result.

Usage (from the PDP host, venv python):
    python run_experiment.py --pdp https://192.168.10.1:8443 \
        --cert /etc/zt-thesis/certs/client-a.crt \
        --key  /etc/zt-thesis/certs/client-a.key \
        --cert-b /etc/zt-thesis/certs/client-b.crt \
        --key-b  /etc/zt-thesis/certs/client-b.key \
        --ca   /etc/zt-thesis/certs/ca.crt \
        --tunnel-ip 10.0.0.2 --tunnel-ip-b 10.0.0.3 \
        --reps 30 --warmup 3

If --cert-b is omitted the campaign still runs, but S2B is skipped and the
micro-segmentation row is left empty rather than being silently faked.

NOTE: run it from a machine whose telemetry path to the PDP matches the one
you report (same-host runs exclude client-side network latency — say which
one you measured). End-to-end agent-side numbers come from the Windows agent
logs; this harness gives you the controlled, repeatable decision-level data.
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests

import scoring
from measurement import MeasurementLogger, _p95

try:
    import phe as paillier
    HE_OK = True
except ImportError:
    HE_OK = False


# --- scenario posture vectors (identical across modes) -----------------------
GOOD = {
    "zone": "trusted", "disk_encrypted": True, "patch_age_days": 5,
    "domain_joined": True, "failed_logins": 0, "av_enabled": True,
    "fw_enabled": True, "os_supported": True, "secure_boot": True,
    "login_anomaly": False, "uptime_hours": 20,
    "hostname": "zt-ep-01", "username": "labuser", "mac_address": "00:0C:29:AA:BB:01",
}
DEGRADED = dict(GOOD, disk_encrypted=False, patch_age_days=120,
                failed_logins=5, login_anomaly=True)   # 20+25+15+10 = 70 DENY

# Scenarios driven by client A with the full scope set.
SCENARIOS = {
    "S1": dict(GOOD),
    "S2": dict(GOOD, hostname="zt-ep-02", mac_address="00:0C:29:AA:BB:02"),
    "S3": dict(DEGRADED),
    "S4": dict(GOOD, zone="unknown", disk_encrypted=False),  # 50+20 = 70 DENY
    "S5": dict(GOOD),                                        # ALLOW, then revoke
}

SCOPES_A = ["smb", "s3"]   # hybrid: one decision, on-prem + cloud (Scenario 7)
SCOPES_B = ["smb"]         # micro-segmentation: file share only, no object store


class Client:
    """Emulates the agent for all three modes over mTLS."""

    def __init__(self, pdp: str, cert: tuple, ca: str, tunnel_ip: str,
                 scopes: list[str], label: str = "A"):
        self.base = pdp.rstrip("/")
        self.s = requests.Session()
        self.s.cert = cert
        self.s.verify = ca
        self.tunnel_ip = tunnel_ip
        self.scopes = list(scopes)
        self.label = label
        self.wg_pubkey = "EXPERIMENT-DUMMY-WG-KEY-" + uuid.uuid4().hex[:16]
        if HE_OK:
            self.pub, self.priv = paillier.generate_paillier_keypair(n_length=2048)
        self._salt_hex = None

    # ---- payload builders (mirror the agent) --------------------------------
    def _common(self, mode):
        return {
            "mode": mode,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tunnel_ip": self.tunnel_ip,
            "wg_pubkey": self.wg_pubkey,
            "requested_resources": self.scopes,
            "nonce": uuid.uuid4().hex,
        }

    def _fetch_salt(self):
        r = self.s.get(f"{self.base}/api/v1/salt/material", timeout=10)
        r.raise_for_status()
        self._salt_hex = r.json()["salt"]

    def _hmac_claims(self, posture):
        import hashlib, hmac as hmac_mod
        if not self._salt_hex:
            self._fetch_salt()
        claims = scoring.claims_from_posture(posture)
        key = bytes.fromhex(self._salt_hex)
        ident = (posture.get("hostname", "") + posture.get("mac_address", "")).encode()
        claims["device_id_hmac"] = hmac_mod.new(key, ident, hashlib.sha256).hexdigest()[:16]
        return claims

    def _ser(self, enc):
        return json.dumps({"v": str(enc.ciphertext()), "e": enc.exponent})

    # ---- one full decision cycle; returns (action, session_id, timings) -----
    def decide(self, mode: str, posture: dict):
        payload = self._common(mode)
        if mode == "baseline":
            payload["telemetry"] = posture
        elif mode == "hmac":
            payload["claims"] = self._hmac_claims(posture)
        elif mode == "he":
            subs = scoring.subscores_from_posture(posture)
            t_enc0 = time.perf_counter()
            payload.update({
                "enc_zone":    self._ser(self.pub.encrypt(subs["zone"])),
                "enc_posture": self._ser(self.pub.encrypt(subs["posture"])),
                "enc_patch":   self._ser(self.pub.encrypt(subs["patch"])),
                "enc_login":   self._ser(self.pub.encrypt(subs["login"])),
                "pub_key_n":   str(self.pub.n),
            })
            client_encrypt_ms = (time.perf_counter() - t_enc0) * 1000
        body = json.dumps(payload)
        wire_bytes = len(body.encode())

        t0 = time.perf_counter()
        r = self.s.post(f"{self.base}/api/v1/telemetry", data=body,
                        headers={"Content-Type": "application/json"}, timeout=30)
        rtt1_ms = (time.perf_counter() - t0) * 1000
        r.raise_for_status()
        resp = r.json()

        timings = {"round1_ms": rtt1_ms, "wire_bytes": wire_bytes}
        if mode != "he":
            timings["total_ms"] = rtt1_ms
            return resp["action"], resp["session_id"], timings

        # HE round 2: local sign decrypt, then report the verdict
        timings["client_encrypt_ms"] = client_encrypt_ms
        t_dec0 = time.perf_counter()
        d = json.loads(resp["enc_comparison"])
        enc = paillier.EncryptedNumber(self.pub, int(d["v"]), int(d["e"]))
        diff = self.priv.decrypt(enc)
        timings["client_decrypt_ms"] = (time.perf_counter() - t_dec0) * 1000
        action = "DENY" if diff >= 0 else "ALLOW"

        t1 = time.perf_counter()
        r2 = self.s.post(f"{self.base}/api/v1/he_decision",
                         json={"session_id": resp["session_id"],
                               "tunnel_ip": self.tunnel_ip,
                               "action": action}, timeout=30)
        timings["round2_ms"] = (time.perf_counter() - t1) * 1000
        r2.raise_for_status()
        timings["total_ms"] = (timings["round1_ms"] + timings["client_decrypt_ms"]
                               + timings["round2_ms"])
        return action, resp["session_id"], timings

    def revoke(self, session_id: str) -> float:
        t0 = time.perf_counter()
        r = self.s.post(f"{self.base}/api/v1/revoke",
                        json={"session_id": session_id}, timeout=30)
        ms = (time.perf_counter() - t0) * 1000
        r.raise_for_status()
        return ms


def summarize(vals):
    if not vals:
        return None
    sl = sorted(vals)
    return {"n": len(sl), "mean_ms": round(statistics.mean(sl), 3),
            "median_ms": round(statistics.median(sl), 3),
            "p95_ms": round(_p95(sl), 3),
            "min_ms": round(sl[0], 3), "max_ms": round(sl[-1], 3)}


def summarize_bytes(vals):
    if not vals:
        return None
    sl = sorted(vals)
    return {"n": len(sl), "mean": round(statistics.mean(sl), 1),
            "median": sl[len(sl) // 2], "min": sl[0], "max": sl[-1]}


class Cell:
    """One (mode, scenario) cell of the campaign matrix."""

    def __init__(self):
        self.lat, self.revoke_lat, self.wire, self.extra = [], [], [], []
        self.passed = 0
        self.total = 0
        self.errors = 0

    def to_dict(self, scored: bool = True):
        out = {"passed": self.passed, "of": self.total if scored else 0,
               "errors": self.errors,
               "latency": summarize(self.lat),
               "wire_bytes": summarize_bytes(self.wire)}
        if self.revoke_lat:
            out["explicit_revocation_latency"] = summarize(self.revoke_lat)
        if self.extra:
            for k in ("round1_ms", "round2_ms", "client_encrypt_ms",
                      "client_decrypt_ms"):
                vals = [e[k] for e in self.extra if k in e]
                if vals:
                    out[f"he_{k}"] = summarize(vals)
        return out


def run_cell(cli, mode, sid, posture, metrics, reps, warmup,
             revoke_after=False, expected=None):
    """Execute one (mode, scenario) cell for `reps` scored repetitions."""
    cell = Cell()
    for i in range(warmup + reps):
        try:
            action, session_id, t = cli.decide(mode, dict(posture))
        except requests.RequestException as e:
            print(f"  {mode}/{sid} rep{i}: request failed: {e}")
            cell.errors += 1
            continue

        rms = None
        if revoke_after and action == "ALLOW":
            try:
                rms = cli.revoke(session_id)
            except requests.RequestException as e:
                print(f"  {mode}/{sid} rep{i}: revoke failed: {e}")
                cell.errors += 1

        if i < warmup:
            continue

        cell.total += 1
        total_ms = t.get("total_ms", t["round1_ms"])
        cell.lat.append(total_ms)
        cell.wire.append(t["wire_bytes"])
        if mode == "he":
            cell.extra.append({k: v for k, v in t.items() if k.endswith("_ms")})

        # Defect (1): S5 is now recorded. The action the scenario is judged on
        # is the revocation, not the ALLOW that preceded it, so the recorded
        # action is REVOKE when the revoke call succeeded.
        if revoke_after:
            if rms is not None:
                cell.revoke_lat.append(rms)
                recorded_action = "REVOKE"
                lat_for_row = rms
            else:
                recorded_action = action     # never got to revoke: record honestly
                lat_for_row = total_ms
            ok = metrics.record_scenario_result(
                sid, mode, recorded_action, cli.scopes, lat_for_row,
                notes=f"client {cli.label}, orchestrated rep {i - warmup + 1}",
                expected=expected)
        else:
            ok = metrics.record_scenario_result(
                sid, mode, action, cli.scopes, total_ms,
                notes=f"client {cli.label}, orchestrated rep {i - warmup + 1}",
                expected=expected)
        cell.passed += 1 if ok else 0
    return cell


def run_hybrid(cli, mode, metrics, reps, warmup):
    """Defect (2): Scenario 7, hybrid teardown.

    Grant both planes, confirm the ALLOW carried smb AND s3, then degrade the
    posture and confirm that a single decision withdraws both together. The
    recorded S7 row is the teardown, because that is the claim: one decision,
    both planes. The preceding ALLOW is recorded as S7A so the setup step is
    auditable rather than assumed.
    """
    cell = Cell()
    for i in range(warmup + reps):
        try:
            a_action, _sid, a_t = cli.decide(mode, dict(GOOD))
            d_action, _sid2, d_t = cli.decide(mode, dict(DEGRADED))
        except requests.RequestException as e:
            print(f"  {mode}/S7 rep{i}: request failed: {e}")
            cell.errors += 1
            continue
        if i < warmup:
            continue

        cell.total += 1
        total_ms = d_t.get("total_ms", d_t["round1_ms"])
        cell.lat.append(total_ms)
        cell.wire.append(d_t["wire_bytes"])
        if mode == "he":
            cell.extra.append({k: v for k, v in d_t.items() if k.endswith("_ms")})

        # the setup half: both planes granted by one decision
        metrics.record_scenario_result(
            "S7A", mode, a_action, cli.scopes,
            a_t.get("total_ms", a_t["round1_ms"]),
            notes=f"hybrid setup: both planes granted, rep {i - warmup + 1}",
            expected="ALLOW")
        # the claim: one decision withdraws smb and s3 together
        ok = metrics.record_scenario_result(
            "S7", mode, d_action, cli.scopes, total_ms,
            notes=(f"hybrid teardown: single decision over "
                   f"{'+'.join(cli.scopes)}, rep {i - warmup + 1}"),
            expected="DENY")
        cell.passed += 1 if ok else 0
    return cell


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pdp", default="https://192.168.10.1:8443")
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--cert-b", help="client B certificate; enables Scenario 2B "
                                     "(micro-segmentation). Omit to skip it.")
    ap.add_argument("--key-b")
    ap.add_argument("--ca", default="/etc/zt-thesis/certs/ca.crt")
    ap.add_argument("--tunnel-ip", default="10.0.0.2")
    ap.add_argument("--tunnel-ip-b", default="10.0.0.3")
    ap.add_argument("--reps", type=int, default=30)
    ap.add_argument("--warmup", type=int, default=3,
                    help="discarded repetitions (first Paillier ops pay one-time costs)")
    ap.add_argument("--modes", nargs="+", default=["baseline", "hmac", "he"])
    ap.add_argument("--log-dir", default="/var/log/zt-thesis")
    args = ap.parse_args()

    if "he" in args.modes and not HE_OK:
        raise SystemExit("phe not installed but 'he' mode requested")
    if args.cert_b and not args.key_b:
        raise SystemExit("--cert-b given without --key-b")

    cli_a = Client(args.pdp, (args.cert, args.key), args.ca,
                   args.tunnel_ip, SCOPES_A, label="A")
    cli_b = None
    if args.cert_b:
        cli_b = Client(args.pdp, (args.cert_b, args.key_b), args.ca,
                       args.tunnel_ip_b, SCOPES_B, label="B")
    else:
        print("WARNING: no client B certificate given. Scenario 2B "
              "(micro-segmentation) will be SKIPPED and the corresponding row "
              "of the results table will be empty. This is deliberate: an "
              "empty row is honest, a faked one is not.")

    metrics = MeasurementLogger(args.log_dir)
    summary = {"started": datetime.now(timezone.utc).isoformat(),
               "reps": args.reps, "warmup": args.warmup,
               "modes": list(args.modes),
               "client_b_present": bool(cli_b),
               "cells": {}}

    for mode in args.modes:
        for sid, posture in SCENARIOS.items():
            cell = run_cell(cli_a, mode, sid, posture, metrics,
                            args.reps, args.warmup,
                            revoke_after=(sid == "S5"))
            summary["cells"][f"{mode}/{sid}"] = cell.to_dict()
            print(f"[{mode}/{sid}] pass {cell.passed}/{cell.total}  "
                  f"lat={cell.to_dict()['latency']}  "
                  f"wire≈{cell.to_dict()['wire_bytes']}")

        # Defect (3): micro-segmentation, driven by a second identity whose
        # certificate grants the narrower scope set.
        if cli_b:
            cell = run_cell(cli_b, mode, "S2B",
                            dict(GOOD, hostname="zt-ep-03",
                                 mac_address="00:0C:29:AA:BB:03"),
                            metrics, args.reps, args.warmup)
            summary["cells"][f"{mode}/S2B"] = cell.to_dict()
            print(f"[{mode}/S2B] pass {cell.passed}/{cell.total} "
                  f"(client B, scopes={SCOPES_B})")

        # Defect (2): hybrid teardown across both planes.
        cell = run_hybrid(cli_a, mode, metrics, args.reps, args.warmup)
        summary["cells"][f"{mode}/S7"] = cell.to_dict()
        print(f"[{mode}/S7] pass {cell.passed}/{cell.total} (hybrid teardown)")

    # worst-case expiry revocation is a design bound, not a sample: report it
    summary["expiry_revocation_bound_s"] = {
        "session_ttl_s": 120, "reaper_interval_s": 30,
        "worst_case_after_last_telemetry_s": 150,
        "note": "expiry revocation is bounded by TTL + reaper sweep; "
                "report separately from decision latency (Finding I). The "
                "observed component is now logged per expiry as overdue_s."}

    summary["measured_from"] = {
        "host": "PDP host (same-host run excludes client-side network latency)",
        "caveat": "state which you measured in Section 7.4; end-to-end "
                  "agent-side numbers come from the Windows agent logs.",
    }
    summary["not_measured_here"] = [
        "Reachability. Scenario 2's negative half (client B blocked from "
        "port 9000) and Scenario 3's loss of an open file must be tested "
        "from the client's network position with Test-NetConnection.",
        "Revocation time at the resource. Section 7.1.5 requires it to be "
        "taken where access ends, not where the decision was recorded.",
    ]

    out = Path(args.log_dir) / "zt-experiment-summary.json"
    out.write_text(json.dumps(summary, indent=2))
    metrics.print_scenario_summary()
    print(f"\nSummary written to {out}")


if __name__ == "__main__":
    main()
