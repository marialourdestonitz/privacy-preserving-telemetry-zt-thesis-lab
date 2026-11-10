#!/usr/bin/env python3
"""
diagnose_modes.py — answer "why does this mode never ALLOW?" from the logs.

Added 2026-08-11, prompted by a dashboard reading. The deployed Grafana panel
showed series for baseline/ALLOW, baseline/DENY, he/ALLOW, he/DENY and
hmac/DENY, together with hmac/REJECT. There was no hmac/ALLOW series at all:
in pseudonymised mode the system had never granted access. A mode that runs
but never allows is worse for the evaluation than a mode that does not run,
because the campaign appears to have three columns of data while one of them
cannot support a comparison. An ALLOW-path latency figure for hmac cannot be
computed from DENY decisions, and Table 7.4's correctness row for Scenario 1
cannot pass.

This script does three things, all from files that already exist on the PDP.

  1. Action distribution per mode. Makes an absent ALLOW impossible to miss.

  2. Score reconstruction for every scored decision. For each record that
     carries a claims or telemetry object, the canonical score is recomputed
     from the logged inputs and the contributing factors are listed. This is
     what turns "hmac denied everything" into "hmac denied everything because
     zone_risk arrived as high", which is a fixable statement.

  3. Rejection triage grouped by reason, with a redacted sample body for each.
     The validation handler records mode "?" when the request body could not
     be parsed at all, so a "?" group means malformed requests rather than a
     mode.

Usage:
    python3 diagnose_modes.py --log-dir /var/log/zt-thesis
    python3 diagnose_modes.py --log-dir /var/log/zt-thesis --mode hmac
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

import scoring

MODES = ("baseline", "hmac", "he")

# Fields never printed, even from a rejected body, so that running this
# diagnostic does not itself create a record of identifiable posture.
REDACT = {"hostname", "host_name", "username", "user", "mac_address", "mac",
          "ip_address", "ip", "sid", "serial", "serial_number", "fqdn",
          "device_id_hmac", "wg_pubkey", "pub_key_n",
          "enc_zone", "enc_posture", "enc_patch", "enc_login"}


def redact(obj):
    if isinstance(obj, dict):
        return {k: ("<redacted>" if k.lower() in REDACT else redact(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, str) and len(obj) > 60:
        return obj[:57] + "..."
    return obj


def read_jsonl(path):
    rows = []
    try:
        with open(path) as f:
            for line in f:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return rows


def factor_breakdown_from_claims(c):
    """Which claims contributed points, and how many. Mirrors
    scoring.score_from_claims term by term so the total is auditable."""
    W = scoring.WEIGHTS
    out = []
    zs = scoring.ZONE_RISK_SCORES.get((c.get("zone_risk") or "").lower(), 50)
    out.append((f"zone_risk={c.get('zone_risk')!r}", zs,
                "unrecognised zone_risk defaults to 50" if zs == 50
                and (c.get("zone_risk") or "").lower() not in
                scoring.ZONE_RISK_SCORES else ""))
    if not c.get("disk_ok", False):
        out.append(("disk_ok=False", W["disk_not_encrypted"], ""))
    pb = (c.get("patch_band") or "very_stale").lower()
    ps = scoring.PATCH_BAND_SCORES.get(pb, W["patch_very_stale"])
    if ps:
        out.append((f"patch_band={pb!r}", ps,
                    "missing patch_band defaults to very_stale"
                    if pb not in scoring.PATCH_BAND_SCORES else ""))
    if not c.get("domain_ok", False):
        out.append(("domain_ok=False", W["not_domain_joined"], ""))
    lb = (c.get("login_band") or "none").lower()
    ls = scoring.LOGIN_BAND_SCORES.get(lb, 0)
    if ls:
        out.append((f"login_band={lb!r}", ls, ""))
    for key, weight, label in (
            ("av_ok", W["av_disabled"], "av_ok=False"),
            ("fw_ok", W["fw_disabled"], "fw_ok=False"),
            ("os_ok", W["os_unsupported"], "os_ok=False"),
            ("secure_boot", W["no_secure_boot"], "secure_boot=False")):
        if not c.get(key, True):
            out.append((label, weight, ""))
    if c.get("login_anomaly", False):
        out.append(("login_anomaly=True", W["login_anomaly"], ""))
    if not c.get("uptime_ok", True):
        out.append(("uptime_ok=False", W["uptime_excessive"], ""))
    return out


def factor_breakdown_from_posture(t):
    subs = scoring.subscores_from_posture(t)
    return [(f"{k} sub-score", v, "") for k, v in subs.items() if v]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-dir", default="/var/log/zt-thesis")
    ap.add_argument("--mode", help="restrict the score reconstruction to one mode")
    ap.add_argument("--samples", type=int, default=3,
                    help="distinct input patterns to print per mode")
    args = ap.parse_args()

    d = Path(args.log_dir)
    decisions = read_jsonl(d / "zt-decisions.jsonl")
    rejections = read_jsonl(d / "zt-rejections.jsonl")

    if not decisions and not rejections:
        raise SystemExit(f"No logs found in {d}")

    # ---------------------------------------------------------------- 1
    print("=" * 72)
    print("1. ACTION DISTRIBUTION PER MODE")
    print("=" * 72)
    dist = defaultdict(Counter)
    for r in decisions:
        if r.get("mode") and r.get("action"):
            dist[r["mode"]][r["action"]] += 1
    for m in rejections:
        pass
    rej_by_mode = Counter(r.get("mode", "?") for r in rejections)

    actions = sorted({a for c in dist.values() for a in c})
    print("mode".ljust(10) + "".join(a.ljust(10) for a in actions) +
          "REJECT".ljust(10))
    for m in list(MODES) + sorted(set(dist) - set(MODES)):
        if m not in dist and m not in rej_by_mode:
            print(m.ljust(10) + "not run")
            continue
        line = m.ljust(10)
        for a in actions:
            line += str(dist[m].get(a, "-")).ljust(10)
        line += str(rej_by_mode.get(m, 0)).ljust(10)
        print(line)
    if rej_by_mode.get("?"):
        print(f"\n{rej_by_mode['?']} rejections carry mode '?'. These are "
              "requests whose body could not be parsed as JSON at all, so the "
              "validation handler had no mode to record. Malformed requests, "
              "not a telemetry mode.")

    print()
    for m in MODES:
        if m in dist and not dist[m].get("ALLOW"):
            print(f"*** {m.upper()} NEVER ALLOWED. {sum(dist[m].values())} "
                  f"decisions, none of them ALLOW. No ALLOW-path latency can "
                  f"be computed for this mode, and the Scenario 1 correctness "
                  f"cell cannot pass. Section 7.4's cross-mode latency "
                  f"comparison is not available for {m} until this is fixed.")
        if m in dist and not dist[m].get("DENY"):
            print(f"*** {m.upper()} NEVER DENIED. Scenarios 3 and 4 cannot "
                  f"have passed in this mode.")

    # ---------------------------------------------------------------- 2
    print()
    print("=" * 72)
    print("2. SCORE RECONSTRUCTION FROM LOGGED INPUTS")
    print("=" * 72)
    print("Recomputed from the claims or telemetry the PDP actually received, "
          "using the canonical scorer. Threshold is "
          f"{scoring.THRESHOLD}; score >= threshold means DENY.\n")

    seen = defaultdict(dict)   # mode -> signature -> (rec, breakdown, score)
    for r in decisions:
        m = r.get("mode")
        if not m or (args.mode and m != args.mode):
            continue
        if "claims" in r:
            inp = r["claims"]
            brk = factor_breakdown_from_claims(inp)
            score = scoring.score_from_claims(inp)
        elif "telemetry" in r:
            inp = r["telemetry"]
            brk = factor_breakdown_from_posture(inp)
            score = scoring.score_from_posture(inp)
        else:
            continue   # he records carry no readable input, by design
        sig = json.dumps([b[0] for b in brk], sort_keys=True)
        if sig not in seen[m]:
            seen[m][sig] = (r, brk, score, 0)
        rec, b, s, n = seen[m][sig]
        seen[m][sig] = (rec, b, s, n + 1)

    for m in sorted(seen):
        print(f"--- {m} ---")
        for sig, (rec, brk, score, n) in list(
                sorted(seen[m].items(), key=lambda kv: -kv[1][3]))[:args.samples]:
            verdict = scoring.decision(score)
            logged = rec.get("action")
            print(f"  {n} records | recomputed score {score} -> {verdict}"
                  f"{'' if logged in (verdict, None) else f'  [LOGGED {logged}: MISMATCH]'}")
            if not brk:
                print("      no factor contributed points (score 0)")
            for name, pts, note in brk:
                print(f"      +{str(pts).rjust(3)}  {name}"
                      f"{'   <-- ' + note if note else ''}")
            print()
        if not seen[m]:
            print("  no readable inputs\n")

    if "he" not in seen:
        print("--- he ---")
        print("  No readable inputs, which is correct and is the point of the "
              "mode: the PDP received ciphertexts and retained no posture and "
              "no score. Its absence from this section is evidence for "
              "Table 7.10, not a gap.\n")

    # ---------------------------------------------------------------- 3
    print("=" * 72)
    print("3. REJECTION TRIAGE")
    print("=" * 72)
    if not rejections:
        print("No rejections.\n")
    else:
        groups = defaultdict(list)
        for r in rejections:
            groups[(r.get("mode", "?"), r.get("reason", "unspecified"))].append(r)
        for (m, reason), rows in sorted(groups.items(),
                                        key=lambda kv: -len(kv[1])):
            print(f"\n{len(rows)} x  mode={m}  reason={reason}")
            body = rows[0].get("payload") or {}
            if body:
                keys = sorted(body) if isinstance(body, dict) else []
                print(f"    keys present: {keys}")
                print(f"    sample (redacted): "
                      f"{json.dumps(redact(body))[:400]}")
            else:
                print("    empty body: the request could not be parsed as "
                      "JSON, or carried no payload.")
            if "timestamp" in str(reason).lower() or "window" in str(reason).lower():
                print("    ACTION: clock skew on the sending machine. "
                      "Re-synchronise and re-run the affected repetitions; "
                      "these are measurement errors, not system behaviour.")
            if reason == "identifier_present":
                print("    ACTION: the privacy guard refused a raw identifier "
                      "in pseudonymised claims. Check which key tripped it "
                      "against PrivacyTransform.FORBIDDEN_KEYS.")
        print()

    print("=" * 72)
    print("Next: fix any mode that never allowed, clear the log directory, "
          "and re-run the campaign in all three modes together. A mode that "
          "denies everything contributes a column of data that cannot be "
          "compared.")


if __name__ == "__main__":
    # Piping into head closes the pipe while this is still writing, which
    # raises BrokenPipeError and prints an alarming traceback for what is
    # simply "the reader stopped reading". Exit quietly instead, so the
    # traceback cannot be mistaken for a fault in the diagnosis.
    try:
        main()
    except BrokenPipeError:
        import os
        import sys
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
