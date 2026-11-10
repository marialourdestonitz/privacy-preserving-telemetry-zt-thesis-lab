#!/usr/bin/env python3
# metrics_exporter.py - plain-HTTP Prometheus exporter, trusted subnet only.
# Serves the same metrics as /api/v1/metrics but without mTLS, bound to
# 192.168.10.1:8000 so only the trusted subnet (and the monitoring VM) can reach it.
#
# Referenced by 06_monitoring/prometheus-grafana-setup.docx (section 2.1).
#
# RESOLVED (review Finding K, 2026-07): this is a separate process with its
# own MeasurementLogger instance, but measurement.py now REBUILDS its counters
# and latency summaries from zt-decisions.jsonl / zt-rejections.jsonl on
# start-up, so this exporter serves real numbers (option (a) of the old
# caveat, implemented). Restart the exporter to pick up new decisions, or
# scrape /api/v1/metrics over mTLS for live in-process values.
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

from measurement import MeasurementLogger

LOG_DIR   = os.environ.get("ZT_LOG_DIR", "/var/log/zt-thesis")
BIND_IP   = os.environ.get("ZT_METRICS_BIND", "192.168.10.1")
BIND_PORT = int(os.environ.get("ZT_METRICS_PORT", "8000"))

METRICS = MeasurementLogger(LOG_DIR)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return
        body = METRICS.prometheus().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):   # silence default logging
        pass


if __name__ == "__main__":
    print(f"metrics exporter on http://{BIND_IP}:{BIND_PORT}/metrics")
    HTTPServer((BIND_IP, BIND_PORT), Handler).serve_forever()
