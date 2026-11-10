#!/usr/bin/env python3

import argparse
import csv
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path

MODES = ["baseline", "hmac", "he"]

SCENARIO_LABELS = {
    "S1":  "1  Good posture -> ALLOW",
    "S2":  "2  Micro-segmentation, client A (smb and s3)",
    "S2B": "2  Micro-segmentation, client B (smb only)",
    "S3":  "3  Posture degradation -> DENY",
    "S4":  "4  Zone change -> DENY",
    "S5":  "5  Explicit revocation",
    "S7A": "7  Hybrid setup (both planes granted)",
    "S7":  "7  Hybrid teardown (one decision, both planes)",
}
SCENARIO_ORDER = ["S1", "S2", "S2B", "S3", "S4", "S5", "S7A", "S7"]

PHASE_LABELS = {
    "decision":  "single-round decision (baseline / hmac)",
    "he_round1": "round 1: encrypted evaluation on the PDP",
    "he_round2": "round 2: client verdict + enforcement",
    "revoke":    "explicit revocation (PDP-side teardown)",
    "expiry":    "reaper expiry (PDP-side teardown)",
}

# Classification for the measured privacy table
IDENTIFIER_FIELDS = {
    "hostname", "username", "mac_address", "device_id", "ip_address",
    "serial", "serial_number", "fqdn", "user", "sid", "upn",
}
PSEUDONYM_FIELDS = {"device_id_hmac"}
SCORE_FIELDS = {"score", "he_eval_ms"}
OPERATIONAL_FIELDS = {
    "ts", "mode", "action", "scope", "session_id", "latency_ms", "phase",
    "tunnel_ip", "prev", "overdue_s", "session_ttl_s", "he_pub_n_bits",
}


def _read_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _read_jsonl(path, limit=None):
    rows = []
    try:
        with open(path) as f:
            for line in f:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
                if limit and len(rows) >= limit:
                    break
    except OSError:
        pass
    return rows


def _read_csv(path):
    try:
        with open(path) as f:
            return list(csv.DictReader(f))
    except OSError:
        return []


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join("" if c is None else str(c) for c in r) + " |")
    return "\n".join(out)

# Table for security outcomes
def table_security(matrix_rows):
    if not matrix_rows:
        return None, ["No zt-scenario-matrix.csv found: the security table "
                      "cannot be produced. Run run_experiment.py first."]

    modes_present = [m for m in MODES
                     if any(r["mode"] == m for r in matrix_rows)]
    extra_modes = sorted({r["mode"] for r in matrix_rows} - set(MODES))
    modes_present += extra_modes

    grid = defaultdict(lambda: [0, 0])
    for r in matrix_rows:
        cell = grid[(r["scenario_id"], r["mode"])]
        cell[1] += 1
        if r["passed"] == "True":
            cell[0] += 1

    sids = [s for s in SCENARIO_ORDER
            if any(r["scenario_id"] == s for r in matrix_rows)]
    sids += sorted({r["scenario_id"] for r in matrix_rows} - set(sids))

    rows = []
    for sid in sids:
        row = [SCENARIO_LABELS.get(sid, sid)]
        for m in modes_present:
            p, t = grid.get((sid, m), (0, 0))
            row.append(f"{p}/{t}" if t else "not run")
        all_cells = [grid.get((sid, m), (0, 0)) for m in modes_present]
        ran = [c for c in all_cells if c[1]]
        row.append("yes" if ran and all(c[0] == c[1] for c in ran)
                   else ("not run" if not ran else "NO"))
        rows.append(row)

    notes = []
    missing = [m for m in MODES if m not in modes_present]
    if missing:
        notes.append(
            f"MODES NOT MEASURED: {', '.join(missing)}. The cross-mode "
            "comparison (Scenario 6, Goal 4) requires baseline, hmac and he. "
            "Any claim of equivalent correctness across modes is unsupported "
            "until all three appear in this table.")

    failing = [r for r in matrix_rows if r["passed"] != "True"]
    if failing:
        by = Counter(f"{r['scenario_id']}/{r['mode']}: expected "
                     f"{r['expected']}, got {r['actual']}"
                     f"{' [' + r['notes'] + ']' if 'SCOPE' in r.get('notes', '') else ''}"
                     for r in failing)
        notes.append("FAILING CELLS (each must be explained in 7.3, not "
                     "omitted):\n" + "\n".join(f"    {k}  x{v}"
                                               for k, v in by.most_common()))

    if not any(r["scenario_id"] == "S2B" for r in matrix_rows):
        notes.append(
            "Scenario 2B (client B, smb only) is absent: the campaign ran "
            "without a client B certificate, so micro-segmentation has no "
            "automated evidence. Pass --cert-b/--key-b to run_experiment.py.")

    notes.append(
        "Reachability is NOT in this table. It cannot be: the harness runs on "
        "the PDP and measures the decision and the granted scope. The negative "
        "half of Scenario 2 (client B refused port 9000) and the loss of an "
        "open file in Scenario 3 are manual Test-NetConnection results and "
        "belong beside this table, clearly labelled as such.")

    return md_table(["Scenario"] + modes_present + ["Correct in all modes run"],
                    rows), notes


# --------------------------------------------------------------------------
# Table: operational behaviour (latency by mode and phase)
# --------------------------------------------------------------------------
def table_latency(latency_report, summary):
    rows = []
    notes = []

    if latency_report:
        for key in sorted(latency_report):
            mode, _, phase = key.partition("/")
            s = latency_report[key]
            rows.append([mode, PHASE_LABELS.get(phase, phase), s["count"],
                         s["mean_ms"], s["median_ms"], s["p95_ms"],
                         s["min_ms"], s["max_ms"]])

    if not rows:
        return None, ["No zt-latency-report.json found. Call "
                      "MeasurementLogger.generate_reports() on the PDP, or "
                      "run the campaign, to produce it."]

    small = [r for r in rows if isinstance(r[2], int) and r[2] < 20]
    if small:
        notes.append(
            "SMALL SAMPLES: " + ", ".join(f"{r[0]}/{r[1]} (n={r[2]})"
                                          for r in small) +
            ". Section 7.1.5 requires that where n is small enough that the "
            "95th percentile approaches the observed maximum, this is stated "
            "with the result. Check those rows: if p95 equals max, say so.")

    for r in rows:
        if r[5] and r[3] and r[5] > 5 * r[3]:
            notes.append(
                f"HEAVY TAIL: {r[0]}/{r[1]} has p95 {r[5]} ms against a mean "
                f"of {r[3]} ms, a ratio of {r[5] / r[3]:.1f}. Section 8.2 "
                "attributes a tail of this shape in hmac mode to the on-demand "
                "salt fetch. Confirm the cause before repeating that "
                "explanation, and rewrite 8.2 if the data says otherwise.")

    modes_seen = {r[0] for r in rows}
    missing = [m for m in MODES if m not in modes_seen]
    if missing:
        notes.append(
            f"NO LATENCY DATA for: {', '.join(missing)}. Section 8.2 compares "
            "the homomorphic round-1 cost against the baseline decision path; "
            "that comparison cannot be made from this table as it stands.")

    return md_table(["Mode", "Phase", "n", "mean ms", "median ms", "p95 ms",
                     "min ms", "max ms"], rows), notes


# --------------------------------------------------------------------------
# Table: payload overhead
# --------------------------------------------------------------------------
def table_wire(summary):
    if not summary or "cells" not in summary:
        return None, []
    per_mode = defaultdict(list)
    for key, cell in summary["cells"].items():
        mode = key.split("/")[0]
        w = cell.get("wire_bytes")
        if w and w.get("mean"):
            per_mode[mode].append(w["mean"])
    if not per_mode:
        return None, []

    base = statistics.mean(per_mode["baseline"]) if per_mode.get("baseline") else None
    rows = []
    for m in MODES:
        if m not in per_mode:
            continue
        mean = statistics.mean(per_mode[m])
        factor = f"{mean / base:.1f}x" if base else "n/a"
        rows.append([m, round(mean, 1), factor])

    notes = ["Payload size is a client-to-PDP measurement taken by the "
             "campaign orchestrator, not a server metric. Four Paillier "
             "ciphertexts at a 2048-bit modulus dominate the homomorphic "
             "payload; this is the bandwidth component of the cost of privacy "
             "and belongs beside the latency figures rather than inside them."]
    return md_table(["Mode", "mean payload bytes", "vs baseline"], rows), notes


# --------------------------------------------------------------------------
# Table: privacy exposure, DERIVED FROM THE LOGS
# --------------------------------------------------------------------------
def _walk_fields(obj, prefix="", out=None):
    if out is None:
        out = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(k)
            _walk_fields(v, f"{prefix}{k}.", out)
    elif isinstance(obj, list):
        for v in obj:
            _walk_fields(v, prefix, out)
    return out


def table_privacy(decisions):
    if not decisions:
        return None, ["No zt-decisions.jsonl found: the privacy table cannot "
                      "be derived and would have to be asserted. Do not "
                      "assert it; run the campaign in all three modes."]

    per_mode_fields = defaultdict(set)
    score_seen = defaultdict(int)
    score_null = defaultdict(int)
    for rec in decisions:
        m = rec.get("mode")
        if not m:
            continue
        per_mode_fields[m] |= _walk_fields(rec)
        if "score" in rec:
            if rec["score"] is None:
                score_null[m] += 1
            else:
                score_seen[m] += 1

    rows = []
    for m in MODES:
        if m not in per_mode_fields:
            rows.append([m, "not run", "not run", "not run", "not run"])
            continue
        f = per_mode_fields[m]
        idents = sorted(f & IDENTIFIER_FIELDS)
        pseudo = sorted(f & PSEUDONYM_FIELDS)
        rows.append([
            m,
            ", ".join(idents) if idents else "none observed",
            ", ".join(pseudo) if pseudo else "none",
            (f"yes ({score_seen[m]} records)" if score_seen[m]
             else f"no (null in {score_null[m]} records)" if score_null[m]
             else "no score field"),
            len(f),
        ])

    notes = [
        "This table is derived from zt-decisions.jsonl by walking every "
        "record and reporting which fields the policy engine actually "
        "retained, rather than by restating the design intent. That is what "
        "makes it evidence.",
        "Read the homomorphic row carefully. A score column reading 'no (null "
        "in N records)' is the load-bearing privacy claim of the thesis: the "
        "PDP wrote a decision record and had no score to put in it. If that "
        "cell ever reads 'yes', the central claim has failed and Chapter 8 "
        "must be rewritten rather than the log ignored.",
    ]
    if "baseline" in per_mode_fields and not (
            per_mode_fields["baseline"] & IDENTIFIER_FIELDS):
        notes.append(
            "Baseline shows no identifiers, which is unexpected: baseline is "
            "supposed to retain them, and it is the control condition that "
            "makes the privacy reduction visible. Check that the campaign "
            "actually sent raw telemetry in baseline mode.")
    if "hmac" in per_mode_fields and (
            per_mode_fields["hmac"] & IDENTIFIER_FIELDS):
        notes.append(
            "IDENTIFIER IN HMAC MODE: raw identifiers appear in pseudonymised "
            "records. This is a privacy defect and a finding. The server-side "
            "guard (contains_identifier) should have rejected it. Investigate "
            "before reporting anything from this row.")
    if score_seen.get("he"):
        notes.append(
            f"SCORE PRESENT IN HOMOMORPHIC MODE: {score_seen['he']} decision "
            "records in he mode carry a non-null score. The whole claim of "
            "this thesis is that the PDP never sees the score in cleartext in "
            "this mode, so this either falsifies the claim or reveals a "
            "logging path that writes a score it should not have. Find which "
            "phase those records are in (decision, he_round1, he_round2, "
            "revoke or expiry) before writing a word of Section 7.5. Do not "
            "report the privacy result until this reads zero.")
    if "he" in per_mode_fields and (
            per_mode_fields["he"] & IDENTIFIER_FIELDS):
        notes.append(
            "IDENTIFIER IN HOMOMORPHIC MODE: the mode that is supposed to "
            "reveal one bit per cycle retained a raw identifier. Treat this "
            "as blocking.")

    return md_table(["Mode", "Raw identifiers retained", "Pseudonymised",
                     "Score visible to PDP", "distinct fields"], rows), notes


# --------------------------------------------------------------------------
# Rejections
# --------------------------------------------------------------------------
REJECTION_EXPLANATIONS = {
    "nonce_replayed": "The same nonce arrived twice inside the freshness "
        "window. Either genuine replay, or the campaign reused a nonce, or a "
        "retry resent an identical body.",
    "session_ip_mismatch": "A session id was presented from a tunnel IP that "
        "does not own it. Client identity is the tunnel IP, so this is the "
        "check that binds a session to its client.",
    "he_decision_ip_mismatch": "A homomorphic verdict was reported for a "
        "session belonging to a different client. Expected if two clients run "
        "concurrently and a session id is crossed; a finding if not.",
    "identifier_present": "Pseudonymised telemetry carried a raw identifier "
        "and was refused. The privacy guard doing its job.",
    "validation_error": "Pydantic rejected the payload. The most common cause "
        "is a timestamp outside the +/-5 s freshness window, which is a "
        "CLOCK SYNCHRONISATION fault on the sending machine, not a property "
        "of the system. Section 7.1.5 makes NTP sync a precondition of every "
        "run for exactly this reason, and Section 5.5 records two such faults.",
}


def table_rejections(rejections):
    if not rejections:
        return None, ["No rejections recorded."]
    counts = Counter((r.get("mode", "?"), r.get("reason", "unspecified"))
                     for r in rejections)
    rows = [[m, reason, n, REJECTION_EXPLANATIONS.get(reason, "Unclassified.")]
            for (m, reason), n in counts.most_common()]
    notes = [
        f"{len(rejections)} rejections total. Every one of these is telemetry "
        "the PDP refused before scoring, so none of them appears in the "
        "decision counts above. A non-trivial rejection count has to be "
        "explained in Section 7.3: it either reflects a defence working as "
        "designed, or a laboratory fault such as clock skew, and the two mean "
        "very different things for the results.",
    ]
    skew = sum(n for (m, reason), n in counts.items()
               if reason in ("validation_error", "timestamp_out_of_window"))
    if skew:
        notes.append(
            f"{skew} rejections look like validation or freshness failures. "
            "Check clock synchronisation on the sending machine before "
            "treating these as a property of the system, and re-run the "
            "affected cells if the clocks were wrong.")
    return md_table(["Mode", "Reason", "Count", "What it means"], rows), notes


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-dir", default="/var/log/zt-thesis")
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--xlsx", action="store_true",
                    help="also write zt-results.xlsx (needs openpyxl)")
    args = ap.parse_args()

    d = Path(args.log_dir)
    out = Path(args.out_dir) if args.out_dir else d
    out.mkdir(parents=True, exist_ok=True)

    summary    = _read_json(d / "zt-experiment-summary.json")
    latency    = _read_json(d / "zt-latency-report.json")
    matrix     = _read_csv(d / "zt-scenario-matrix.csv")
    decisions  = _read_jsonl(d / "zt-decisions.jsonl")
    rejections = _read_jsonl(d / "zt-rejections.jsonl")

    sections = []
    sections.append(
        "# Chapter 7 results tables\n\n"
        f"Generated by `analyze_campaign.py` from `{d}`.\n\n"
        "Every table below is produced from campaign output. Notes marked in "
        "capitals are conditions that must be resolved or stated in the text "
        "before the table is used; they are not decoration.\n\n"
        "Tables 7.3 (parity), 7.5 (reachability) and 7.8 (revocation timing) "
        "are not produced here. Parity comes from test_scoring_parity.py, and "
        "reachability and revocation timing are measured at the client and at "
        "the resource, which this script cannot observe from the policy "
        "engine. Fill those three by hand from the manual runs.\n")

    if summary:
        sections.append(
            f"Campaign started {summary.get('started', '?')} · "
            f"{summary.get('reps', '?')} scored repetitions per cell "
            f"({summary.get('warmup', '?')} discarded as warm-up) · "
            f"modes: {', '.join(summary.get('modes', []))} · "
            f"client B present: {summary.get('client_b_present')}\n")

    for title, (tbl, notes) in [
        # Numbering matches Chapter-07-Sections-7.2-to-7.6-Results.docx, which
        # continues from Tables 7.1 and 7.2 in the Research Method section.
        ("Table 7.4 - Decision correctness by scenario and telemetry mode",
         table_security(matrix)),
        ("Table 7.6 - Rejected telemetry by reason", table_rejections(rejections)),
        ("Table 7.7 - Decision latency by mode and protocol phase",
         table_latency(latency, summary)),
        ("Table 7.9 - Telemetry payload size by mode", table_wire(summary)),
        ("Table 7.10 - Privacy exposure, derived from the decision log",
         table_privacy(decisions)),
    ]:
        sections.append(f"\n## {title}\n")
        sections.append(tbl if tbl else "_No data._")
        for n in notes:
            sections.append(f"\n> {n}\n")

    if summary and "expiry_revocation_bound_s" in summary:
        b = summary["expiry_revocation_bound_s"]
        sections.append(
            "\n## Revocation bound\n\n"
            f"Session TTL {b['session_ttl_s']} s + reaper interval "
            f"{b['reaper_interval_s']} s = "
            f"{b['worst_case_after_last_telemetry_s']} s worst case after the "
            "last telemetry report. This is a design bound, not a measurement. "
            "The measured revocation time is taken at the resource and must be "
            "reported separately.\n")

    md = "\n".join(sections) + "\n"
    md_path = out / "zt-chapter7-tables.md"
    md_path.write_text(md)
    print(md)
    print(f"\nWritten: {md_path}")

    if args.xlsx:
        try:
            _write_xlsx(out / "zt-results.xlsx", matrix, latency, summary,
                        decisions, rejections)
            print(f"Written: {out / 'zt-results.xlsx'}")
        except ImportError:
            print("openpyxl not installed; skipped xlsx "
                  "(pip install openpyxl)")


def _write_xlsx(path, matrix, latency, summary, decisions, rejections):
    from openpyxl import Workbook
    from openpyxl.styles import Font

    wb = Workbook()
    ws = wb.active
    ws.title = "scenario matrix"
    if matrix:
        headers = list(matrix[0].keys())
        ws.append(headers)
        for c in ws[1]:
            c.font = Font(bold=True)
        for r in matrix:
            ws.append([r.get(h) for h in headers])

    ws2 = wb.create_sheet("latency")
    ws2.append(["mode", "phase", "n", "mean_ms", "median_ms", "p95_ms",
                "min_ms", "max_ms"])
    for c in ws2[1]:
        c.font = Font(bold=True)
    for key in sorted(latency or {}):
        mode, _, phase = key.partition("/")
        s = latency[key]
        ws2.append([mode, phase, s["count"], s["mean_ms"], s["median_ms"],
                    s["p95_ms"], s["min_ms"], s["max_ms"]])

    ws3 = wb.create_sheet("rejections")
    ws3.append(["mode", "reason", "count"])
    for c in ws3[1]:
        c.font = Font(bold=True)
    for (m, reason), n in Counter(
            (r.get("mode", "?"), r.get("reason", "unspecified"))
            for r in rejections).most_common():
        ws3.append([m, reason, n])

    wb.save(path)


if __name__ == "__main__":
    main()
