"""
measurement.py — decision logging, Prometheus exposition, scenario matrix.

REVISED per the implementation review 2026-07:
  Finding J: counters and latency summaries are now REBUILT from
             zt-decisions.jsonl / zt-rejections.jsonl on start-up, so
             (a) metrics survive a PDP restart, and (b) the standalone
             metrics_exporter.py process serves real numbers instead of an
             empty registry.
  Finding I: records carry a 'phase' field (decision / he_round1 / he_round2 /
             revoke / expiry) so revocation latency and decision latency can
             be reported separately; the latency report is broken out by
             (mode, phase).
  Hygiene:   p95 index off-by-one fixed; per-key latency lists are bounded
             (deque, maxlen 50k) so a long campaign cannot exhaust memory;
             unused imports removed.

REVISED 2026-08-11 (evaluation readiness):
  record_scenario_result() now carries an explicit EXPECTED_ACTION map instead
  of an expected_deny set, so Scenario 5 (REVOKE) and Scenario 7 (hybrid) can
  be recorded at all — previously neither could appear in the scenario matrix,
  which left two rows of the evaluation table permanently unfillable. A scope
  assertion was added so that Scenario 2 tests micro-segmentation (client B
  must hold smb and must not hold s3) rather than merely recording that two
  clients were allowed.

  Three further defects were found by reading the deployed Grafana dashboard
  against this code:

  (1) zt_decisions_total mixed real access decisions (ALLOW / DENY / REVOKE)
      with protocol bookkeeping (EVAL, the HE round-1 pending record, and
      EXPIRE, the reaper record). Every homomorphic cycle emits one EVAL AND
      one ALLOW/DENY, so a cross-mode comparison of "decisions" showed the
      homomorphic mode with roughly twice the count of baseline purely as an
      artifact of the protocol having two rounds. Bookkeeping now goes to
      zt_protocol_events_total and is excluded from the decision counter.

  (2) Rejections were counted per mode with no reason, so the rejection panel
      could show a number but never what caused it. The reason is now a label
      on zt_rejections_total.

  (3) The standalone exporter built its state once at process start and never
      re-read the logs, so the dashboard served a frozen snapshot that only
      advanced when the exporter was restarted. refresh() now tails both logs
      incrementally from a stored byte offset and is called before every
      exposition, so panels advance live without a restart.

  The privacy constraint of PR4 is unchanged: every series added here is an
  aggregate over mode, phase, action or reason. No identifier, no per-device
  series, and no score is exposed.
"""
import csv
import json
import re
import statistics
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

_LAT_MAXLEN = 50_000

# Actions that represent an actual access decision, i.e. a change in what the
# client may reach. These are the only values that belong in the decision
# counter, because these are the only ones that are comparable across modes.
DECISION_ACTIONS = {"ALLOW", "DENY", "REVOKE"}

# Protocol bookkeeping. Real records, useful to chart, but not decisions:
#   EVAL        the homomorphic round-1 record; the decision does not exist yet
#   PENDING_HE  the session placeholder written alongside it
#   EXPIRE      the reaper's record when a session ages out
PROTOCOL_EVENTS = {"EVAL", "PENDING_HE", "EXPIRE"}


def _p95(sorted_vals):
    """95th percentile with a correct index for small n."""
    if not sorted_vals:
        return None
    idx = max(0, min(len(sorted_vals) - 1,
                     round(0.95 * (len(sorted_vals) - 1))))
    return sorted_vals[idx]


class MeasurementLogger:
    def __init__(self, log_dir="/var/log/zt-thesis"):
        self.log_dir        = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.decisions_path = self.log_dir / "zt-decisions.jsonl"
        self.rejections_path = self.log_dir / "zt-rejections.jsonl"
        self._baseline_records = []
        # latency keyed by (mode, phase) — Finding I
        self._latencies = defaultdict(lambda: deque(maxlen=_LAT_MAXLEN))
        # running counters for the Prometheus endpoint
        self._counts = defaultdict(int)      # ("baseline","ALLOW") -> n
        self._events = defaultdict(int)      # ("he","EVAL")        -> n
        self._rejects = defaultdict(int)     # ("he","nonce_replayed") -> n
        # byte offsets for incremental tailing, so a long-lived exporter
        # process picks up new records without being restarted
        self._offsets = {}
        self.refresh()

    # ------------------------------------------------------------------
    # Rebuild in-memory state from the persistent logs (Finding J), and
    # thereafter tail them incrementally (2026-08-11).
    #
    # refresh() is idempotent and cheap: it seeks to the offset it stopped at
    # last time and reads only what has been appended since. Calling it before
    # every exposition is what makes the standalone exporter serve live data.
    # If a log is rotated (the file shrinks below the stored offset) the offset
    # is reset and the file is re-read from the beginning.
    # ------------------------------------------------------------------
    def refresh(self):
        self._tail(self.decisions_path, self._ingest_decision_line)
        self._tail(self.rejections_path, self._ingest_rejection_line)

    def _tail(self, path, handler):
        if not path.exists():
            return
        try:
            size = path.stat().st_size
            start = self._offsets.get(path, 0)
            if size < start:          # rotated or truncated: start over
                start = 0
            if size == start:         # nothing new
                return
            with open(path) as f:
                f.seek(start)
                for line in f:
                    try:
                        handler(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                self._offsets[path] = f.tell()
        except OSError:
            pass

    def _ingest_decision_line(self, rec):
        self._ingest(rec, persist=False)

    def _ingest_rejection_line(self, rec):
        m = rec.get("mode")
        if m:
            self._rejects[(m, self._reason_label(rec.get("reason")))] += 1

    # Retained under its old name: other code and the docs refer to _replay.
    def _replay(self):
        self.refresh()

    def _ingest(self, rec, persist=True):
        if persist:
            with open(self.decisions_path, "a") as f:
                f.write(json.dumps(rec) + "\n")
            # keep our own offset past what we just wrote, so a later refresh()
            # does not count this record a second time
            try:
                self._offsets[self.decisions_path] = self.decisions_path.stat().st_size
            except OSError:
                pass
        m = rec.get("mode")
        a = rec.get("action")
        phase = rec.get("phase", "decision")
        if m == "baseline" and rec.get("telemetry"):
            self._baseline_records.append(rec["telemetry"])
        if rec.get("latency_ms") is not None:
            self._latencies[(m, phase)].append(rec["latency_ms"])
        if m and a:
            # Split real access decisions from protocol bookkeeping so that
            # decision counts are comparable across modes. Without this the
            # two-round homomorphic protocol inflates its own decision count.
            if a in PROTOCOL_EVENTS:
                self._events[(m, a)] += 1
            elif a in DECISION_ACTIONS:
                self._counts[(m, a)] += 1
            else:
                # unknown action value: count it, but keep it out of both
                # curated series so it cannot silently distort a comparison
                self._events[(m, a)] += 1

    # ------------------------------------------------------------------
    # Decision logging. Accepts a single dict (what pdp_server.py sends)
    # OR the older positional form, so both callers work.
    # ------------------------------------------------------------------
    def log_decision(self, record=None, *, mode=None, score=None,
                     action=None, scope=None, latency_ms=None,
                     device_id=None, raw_telemetry=None, prev_decision=None,
                     **extra):
        # Normalise to a dict regardless of how we were called
        if isinstance(record, dict):
            rec = dict(record)
        else:
            rec = {
                "device_id":  device_id,
                "mode":       mode,
                "score":      score,
                "action":     action,
                "scope":      scope,
                "latency_ms": round(latency_ms, 3) if latency_ms is not None else None,
                "prev":       prev_decision,
            }
            if raw_telemetry:
                rec["telemetry"] = raw_telemetry
        rec.setdefault("ts", datetime.now(timezone.utc).isoformat())
        rec.setdefault("phase", "decision")
        self._ingest(rec, persist=True)

    # ------------------------------------------------------------------
    # Rejection logging (telemetry that failed validation / privacy check)
    # ------------------------------------------------------------------
    @staticmethod
    def _reason_label(reason):
        """Normalise a rejection reason into a bounded metric label.

        Pydantic embeds the offending value in its message, so a freshness
        failure arrives as "timestamp out of window (skew=11073.4s)" and the
        next one as "(skew=11074.1s)". Used directly as a Prometheus label
        that produces a new time series per rejection: unbounded cardinality,
        a panel showing a count of 1 on every row, and a needless load on the
        monitoring host. The full reason, skew value and all, is still written
        to zt-rejections.jsonl, which is where diagnosis happens; only the
        metric label is collapsed to the class of fault.
        """
        r = (reason or "unspecified").lower()
        if "timestamp" in r or "window" in r or "skew" in r:
            return "timestamp_out_of_window"
        if "nonce" in r:
            return "nonce_replayed"
        if "identifier" in r:
            return "identifier_present"
        if "session" in r and "mismatch" in r:
            return "session_ip_mismatch"
        if "validation" in r or "value error" in r:
            return "validation_error"
        # collapse anything still carrying digits, so an unclassified reason
        # cannot reintroduce the cardinality problem
        return re.sub(r"[0-9]+(\.[0-9]+)?", "N", r)[:60].strip()

    def log_rejection(self, mode, reason, payload=None):
        rec = {
            "ts":     datetime.now(timezone.utc).isoformat(),
            "mode":   mode,
            "reason": reason,
            "payload": payload if payload is not None else {},
        }
        with open(self.rejections_path, "a") as f:
            f.write(json.dumps(rec) + "\n")
            try:
                self._offsets[self.rejections_path] = self.rejections_path.stat().st_size
            except OSError:
                pass
        self._rejects[(mode, self._reason_label(reason))] += 1

    # ------------------------------------------------------------------
    # Prometheus exposition (text format) for the /api/v1/metrics endpoint
    #
    # Every series here is an aggregate over mode, action, phase or reason.
    # No identifier, no per-device series and no score is exposed: this is
    # requirement PR4, and it is the reason the aggregation happens on the PDP
    # rather than by shipping raw decision records to the monitoring host.
    # ------------------------------------------------------------------
    def prometheus(self):
        # pick up anything appended since the last scrape (2026-08-11)
        self.refresh()
        lines = [
            "# HELP zt_decisions_total Access decisions by mode and action. "
            "ALLOW, DENY and REVOKE only: these are the outcomes that change "
            "what a client may reach, and they are directly comparable across "
            "modes. Protocol bookkeeping is in zt_protocol_events_total.",
            "# TYPE zt_decisions_total counter",
        ]
        for (mode, action), n in sorted(self._counts.items()):
            lines.append(
                f'zt_decisions_total{{mode="{mode}",action="{action}"}} {n}')

        lines.append(
            "# HELP zt_protocol_events_total Protocol bookkeeping by mode and "
            "event: EVAL is the homomorphic round-1 record written before any "
            "decision exists, EXPIRE is the reaper ageing a session out. These "
            "are deliberately NOT decisions; counting them as such would show "
            "the two-round homomorphic mode with roughly twice the decision "
            "count of baseline as an artifact of the protocol.")
        lines.append("# TYPE zt_protocol_events_total counter")
        for (mode, event), n in sorted(self._events.items()):
            lines.append(
                f'zt_protocol_events_total{{mode="{mode}",event="{event}"}} {n}')

        lines.append(
            "# HELP zt_rejections_total Telemetry rejected before scoring, by "
            "mode and reason. The reason label is what makes a rejection count "
            "diagnosable rather than merely visible.")
        lines.append("# TYPE zt_rejections_total counter")
        for (mode, reason), n in sorted(self._rejects.items()):
            lines.append(
                f'zt_rejections_total{{mode="{mode}",reason="{reason}"}} {n}')

        lines.append("# HELP zt_latency_ms_mean Mean latency by mode and phase.")
        lines.append("# TYPE zt_latency_ms_mean gauge")
        for (mode, phase), lats in sorted(self._latencies.items()):
            if lats:
                lines.append(
                    f'zt_latency_ms_mean{{mode="{mode}",phase="{phase}"}} '
                    f'{round(statistics.mean(lats), 3)}')
        lines.append("# HELP zt_latency_ms_p95 p95 latency by mode and phase.")
        lines.append("# TYPE zt_latency_ms_p95 gauge")
        for (mode, phase), lats in sorted(self._latencies.items()):
            if lats:
                p = _p95(sorted(lats))
                lines.append(
                    f'zt_latency_ms_p95{{mode="{mode}",phase="{phase}"}} '
                    f'{round(p, 3)}')
        return "\n".join(lines) + "\n"

    # ------------------------------------------------------------------
    # HE timing log (kept from your version)
    # ------------------------------------------------------------------
    def log_he_evaluation(self, device_id, he_ms, total_ms):
        rec = {"ts": datetime.now(timezone.utc).isoformat(),
               "device_id": device_id, "mode": "he",
               "he_eval_ms": he_ms, "total_ms": total_ms}
        with open(self.decisions_path, "a") as f:
            f.write(json.dumps(rec) + "\n")

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------
    def generate_reports(self):
        self._latency_report()
        print(f"Reports in {self.log_dir}")

    def _latency_report(self):
        report = {}
        for (mode, phase), lats in self._latencies.items():
            if lats:
                sl = sorted(lats)
                report[f"{mode}/{phase}"] = {
                    "count":     len(sl),
                    "mean_ms":   round(statistics.mean(sl), 3),
                    "median_ms": round(statistics.median(sl), 3),
                    "p95_ms":    round(_p95(sl), 3),
                    "min_ms":    round(sl[0], 3),
                    "max_ms":    round(sl[-1], 3),
                }
        path = self.log_dir / "zt-latency-report.json"
        path.write_text(json.dumps(report, indent=2))

    # ------------------------------------------------------------------
    # Scenario matrix
    # ------------------------------------------------------------------
    # Expected action per scenario ID. Scenario IDs match MT-test-scenarios
    # (Scenarios 1-7). Kept as an explicit map rather than an expected_deny set
    # so that every row of the evaluation table is reachable:
    #   S1  good posture                    -> ALLOW
    #   S2  micro-segmentation, client A    -> ALLOW  (both scopes)
    #   S2B micro-segmentation, client B    -> ALLOW  (smb scope only; the
    #                                         negative half is asserted on the
    #                                         granted scope set, see below)
    #   S3  posture degradation             -> DENY
    #   S4  zone change                     -> DENY
    #   S5  explicit revocation             -> REVOKE (previously unreachable:
    #                                         nothing recorded an S5 row)
    #   S7  hybrid teardown, both planes    -> DENY   (previously absent)
    EXPECTED_ACTION = {
        "S1": "ALLOW", "S2": "ALLOW", "S2B": "ALLOW",
        "S3": "DENY",  "S4": "DENY",
        "S5": "REVOKE",
        "S7A": "ALLOW",   # hybrid setup: both planes granted
        "S7": "DENY",     # hybrid teardown: one decision withdraws both
    }

    # Scopes the decision must have carried, where the scenario makes a claim
    # about scope rather than only about the action. This is what turns
    # Scenario 2 from "two clients were allowed" into an actual test of
    # micro-segmentation: client B must be granted smb and must NOT be
    # granted s3. A row fails if the action is right but the scope is wrong.
    EXPECTED_SCOPES = {
        "S2":  {"required": {"smb", "s3"}, "forbidden": set()},
        "S2B": {"required": {"smb"},       "forbidden": {"s3"}},
        "S7A": {"required": {"smb", "s3"}, "forbidden": set()},
        "S7":  {"required": {"smb", "s3"}, "forbidden": set()},
    }

    def record_scenario_result(self, scenario_id, mode,
                               actual_action, scope_received,
                               latency_ms, notes="", expected=None):
        scope_set = set(scope_received)
        if expected is None:
            expected = self.EXPECTED_ACTION.get(scenario_id, "ALLOW")
        passed = actual_action == expected

        # scope assertion, where the scenario makes one
        scope_rule = self.EXPECTED_SCOPES.get(scenario_id)
        scope_ok = True
        if scope_rule:
            missing = scope_rule["required"] - scope_set
            leaked  = scope_rule["forbidden"] & scope_set
            scope_ok = not missing and not leaked
            if missing:
                notes = f"{notes} | MISSING SCOPE: {sorted(missing)}".strip(" |")
            if leaked:
                notes = f"{notes} | SCOPE LEAK: {sorted(leaked)}".strip(" |")
            passed = passed and scope_ok

        row = {"scenario_id": scenario_id, "mode": mode,
               "expected": expected, "actual": actual_action,
               "scope": ",".join(scope_received),
               "scope_ok": scope_ok,
               "latency_ms": round(latency_ms, 3),
               "passed": passed, "notes": notes,
               "ts": datetime.now(timezone.utc).isoformat()}
        path = self.log_dir / "zt-scenario-matrix.csv"
        write_header = not path.exists()
        with open(path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=row.keys())
            if write_header:
                writer.writeheader()
            writer.writerow(row)
        return passed

    def print_scenario_summary(self):
        """Scenario x mode grid.

        Printed as a grid rather than a single ratio because the single ratio
        hid the most important fact about the campaign so far: that only one
        telemetry mode had ever been run. An empty column is the thing you
        most need to see, so empty cells are printed as '-' and counted.
        """
        path = self.log_dir / "zt-scenario-matrix.csv"
        if not path.exists():
            print("No scenario results yet.")
            return
        with open(path) as f:
            rows = list(csv.DictReader(f))
        if not rows:
            print("Scenario matrix is empty.")
            return

        total  = len(rows)
        passed = sum(1 for r in rows if r["passed"] == "True")

        modes = sorted({r["mode"] for r in rows})
        order = [s for s in ("S1", "S2", "S2B", "S3", "S4", "S5", "S7A", "S7")
                 if any(r["scenario_id"] == s for r in rows)]
        order += sorted({r["scenario_id"] for r in rows} - set(order))

        grid = defaultdict(lambda: [0, 0])   # (sid, mode) -> [passed, total]
        for r in rows:
            cell = grid[(r["scenario_id"], r["mode"])]
            cell[1] += 1
            if r["passed"] == "True":
                cell[0] += 1

        w = max(10, max((len(m) for m in modes), default=10) + 2)
        print(f"\n=== Scenario Summary: {passed}/{total} passed ===")
        print("scenario".ljust(10) + "".join(m.ljust(w) for m in modes))
        for sid in order:
            line = sid.ljust(10)
            for m in modes:
                p, t = grid.get((sid, m), (0, 0))
                line += (f"{p}/{t}" if t else "-").ljust(w)
            print(line)

        missing = [m for m in ("baseline", "hmac", "he") if m not in modes]
        if missing:
            print(f"\nNOT MEASURED: {', '.join(missing)}. "
                  "The cross-mode comparison (Scenario 6, Goal 4) needs all "
                  "three; results from a single mode cannot support it.")
        failed = [r for r in rows if r["passed"] != "True"]
        if failed:
            print(f"\n{len(failed)} failing rows. First few:")
            for r in failed[:5]:
                print(f"  {r['scenario_id']}/{r['mode']}: "
                      f"expected {r['expected']}, got {r['actual']}  "
                      f"{r.get('notes', '')}")
