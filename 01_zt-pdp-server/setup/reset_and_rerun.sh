#!/usr/bin/env bash
# reset_and_rerun.sh — archive the old campaign, start a clean one.
#
# Run on the PDP (192.168.10.1). Added 2026-08-11.
#
# WHY THE ORDER MATTERS. The existing logs contain the only evidence of why
# pseudonymised mode never allowed anything. Deleting them and re-running
# would reproduce the same broken column with nothing left to diagnose it
# from. So this script diagnoses first, archives second, and never deletes.
#
#   ./reset_and_rerun.sh diagnose    read the current logs, change nothing
#   ./reset_and_rerun.sh archive     move them aside, restart services
#   ./reset_and_rerun.sh run         run the campaign in all three modes
#   ./reset_and_rerun.sh verify      check the exporter and generate tables
#
# Run them in that order. Each step prints what to look at before the next.

set -euo pipefail

LOG_DIR="${ZT_LOG_DIR:-/var/log/zt-thesis}"
PDP_DIR="${ZT_PDP_DIR:-/opt/zt-thesis/pdp}"
CERT_DIR="${ZT_CERT_DIR:-/etc/zt-thesis/certs}"
PY="${ZT_PYTHON:-/opt/zt-thesis/venv/bin/python3}"
STAMP="$(date +%F-%H%M)"

cd "$PDP_DIR"

step_diagnose() {
  echo "=== Parity precondition (Table 7.3) ==="
  "$PY" test_scoring_parity.py

  echo
  echo "=== Diagnosing the CURRENT logs before anything is moved ==="
  "$PY" diagnose_modes.py --log-dir "$LOG_DIR" | tee "/tmp/zt-diagnosis-$STAMP.txt"

  echo
  echo "Saved to /tmp/zt-diagnosis-$STAMP.txt"
  cat <<'EOF'

READ THREE THINGS IN THAT OUTPUT BEFORE CONTINUING.

  1. Does any mode show a dash under ALLOW? If hmac still never allowed,
     re-running the campaign will reproduce the same unusable column. Fix the
     cause first. The score reconstruction section names the factor that
     pushed each decision over the threshold.

  2. Does any record carry [LOGGED ...: MISMATCH]? That means the action in
     the log disagrees with the score recomputed from that record's own
     claims, so the mode is deciding on something other than the score. The
     parity test cannot catch this: it exercises scoring.py, not the deployed
     request path.

  3. What are the rejections? A reason mentioning timestamp or window is
     clock skew on the sending machine, which invalidates the repetitions
     around it. A group with mode "?" is malformed request bodies.

When you have an answer for all three, run:  ./reset_and_rerun.sh archive
EOF
}

step_archive() {
  local dest="$LOG_DIR/archive-$STAMP"
  echo "=== Stopping the exporter so it is not reading a moving target ==="
  sudo systemctl stop zt-metrics || true

  echo "=== Archiving to $dest (nothing is deleted) ==="
  sudo mkdir -p "$dest"
  shopt -s nullglob
  for f in "$LOG_DIR"/zt-*.jsonl "$LOG_DIR"/zt-*.csv "$LOG_DIR"/zt-*.json; do
    sudo mv "$f" "$dest/"
    echo "  moved $(basename "$f")"
  done
  shopt -u nullglob
  sudo cp "/tmp/zt-diagnosis-$STAMP.txt" "$dest/" 2>/dev/null || true

  echo "=== Restarting with empty counters ==="
  sudo systemctl restart zt-pdp
  sleep 2
  sudo systemctl start zt-metrics
  sudo systemctl --no-pager --lines=0 status zt-pdp zt-metrics || true

  echo
  echo "Counters are now empty. The PDP rebuilds them from the log files, so"
  echo "moving the files aside is what resets the dashboard. Old data is in"
  echo "$dest and can be moved back if you need it."
  echo
  echo "Next:  ./reset_and_rerun.sh run"
}

step_run() {
  echo "=== Clock check. Telemetry outside a 5 s window is refused ==="
  chronyc tracking | grep -E "System time|Last offset" || true
  echo "Confirm the offset is well under a second. Re-sync the Windows"
  echo "clients too (w32tm /resync) before continuing."
  echo
  read -r -p "Clocks synchronised on every machine? [y/N] " ok
  [[ "$ok" == "y" || "$ok" == "Y" ]] || { echo "Stopping."; exit 1; }

  local B_ARGS=()
  if [[ -f "$CERT_DIR/client-b.crt" ]]; then
    B_ARGS=(--cert-b "$CERT_DIR/client-b.crt" --key-b "$CERT_DIR/client-b.key")
  else
    echo "WARNING: $CERT_DIR/client-b.crt not found."
    echo "Scenario 2B will be skipped and micro-segmentation will have no"
    echo "automated evidence. An empty row is honest; a faked one is not."
  fi

  echo "=== Campaign: all three modes in one invocation ==="
  echo "Running them together is what makes the comparison valid. Separate"
  echo "sessions would reintroduce the machine-state variation the"
  echo "repeated-measures design exists to remove."
  "$PY" run_experiment.py \
    --pdp https://192.168.10.1:8443 \
    --cert "$CERT_DIR/client-a.crt" \
    --key  "$CERT_DIR/client-a.key" \
    "${B_ARGS[@]}" \
    --ca "$CERT_DIR/ca.crt" \
    --tunnel-ip 10.0.0.2 --tunnel-ip-b 10.0.0.3 \
    --reps 30 --warmup 3 \
    --modes baseline hmac he \
    --log-dir "$LOG_DIR"

  echo
  echo "Check the scenario grid above: three populated mode columns, no"
  echo "failing cells, and an S2B row."
  echo
  echo "Next:  ./reset_and_rerun.sh verify"
}

step_verify() {
  echo "=== Exporter, from the PDP ==="
  curl -s http://192.168.10.1:8000/metrics | grep -E "^zt_" | head -40 || true

  echo
  echo "=== Four things that should now be true ==="
  local m; m="$(curl -s http://192.168.10.1:8000/metrics || true)"
  for mode in baseline hmac he; do
    if grep -q "zt_decisions_total{mode=\"$mode\",action=\"ALLOW\"}" <<<"$m"; then
      echo "  OK    $mode has an ALLOW series"
    else
      echo "  FAIL  $mode has NO ALLOW series. This mode cannot support a"
      echo "        latency comparison. Do not write Section 7.4 from it."
    fi
  done
  grep -q "zt_protocol_events_total" <<<"$m" \
    && echo "  OK    EVAL and EXPIRE are separated from decisions" \
    || echo "  FAIL  protocol events missing: deploy the revised measurement.py"
  grep -q "zt_rejections_total{.*reason=" <<<"$m" \
    && echo "  OK    rejections carry a reason label" \
    || echo "  note  no rejections recorded, or old measurement.py deployed"

  echo
  echo "=== Re-running the diagnosis on the fresh logs ==="
  "$PY" diagnose_modes.py --log-dir "$LOG_DIR" | head -30

  echo
  echo "=== Generating the Chapter 7 tables ==="
  "$PY" analyze_campaign.py --log-dir "$LOG_DIR" --xlsx

  cat <<EOF

Written to $LOG_DIR:
  zt-chapter7-tables.md   Tables 7.4, 7.6, 7.7, 7.9, 7.10, populated
  zt-results.xlsx         the same as a workbook

Still to fill by hand, because the harness runs on the PDP and cannot see them:
  Table 7.3  parity, from the test run at the start of this script
  Table 7.5  reachability, from Test-NetConnection on the Windows clients
  Table 7.8  revocation timed AT THE RESOURCE, three readings each

In Grafana, import 10_code_by_vm/06_zt-monitoring/grafana-dashboard-zt.json
before looking at the panels. The metric names changed, so the old dashboard
will show empty panels against the new exporter.
EOF
}

case "${1:-}" in
  diagnose) step_diagnose ;;
  archive)  step_archive ;;
  run)      step_run ;;
  verify)   step_verify ;;
  *) echo "usage: $0 {diagnose|archive|run|verify}   (in that order)"; exit 1 ;;
esac
