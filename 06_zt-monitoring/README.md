# Machine 6: zt-monitoring (deployed)

Observability for the laboratory. Its design constraint is unusual and worth stating plainly: monitoring a privacy-preserving system must not reintroduce the exposure the system exists to remove.

**Address:** 192.168.10.50 on the trusted segment
**Scrapes:** the PDP's metrics exporter at 192.168.10.1:8000, every 15 seconds
**Prometheus:** port 9090 · **Grafana:** port 3000

---

## The privacy constraint

The exporter on the PDP publishes aggregates only:

- `zt_decisions_total{mode,action}`: access decisions. ALLOW, DENY and REVOKE only
- `zt_protocol_events_total{mode,event}`: protocol bookkeeping. EVAL and EXPIRE
- `zt_rejections_total{mode,reason}`: telemetry refused before scoring
- `zt_latency_ms_mean{mode,phase}` and `zt_latency_ms_p95{mode,phase}`: latency by mode and phase

There is no per-device series, no identifier, and no score. A dashboard can therefore show that the system denied several hundred requests in homomorphic mode without revealing which device was denied or why. This is requirement PR4 in the specification, and it is the reason the exporter aggregates on the PDP rather than shipping raw decision records to a monitoring host.

The phase labels matter for the evaluation: they are what allow the homomorphic evaluation cost in round one to be charted separately from enforcement time in round two, so the cryptographic overhead is not confused with network latency.

---

## Why this is a separate machine

Grafana occupies roughly 300 MB of memory across more than twenty threads. Co-locating it on the PDP would put that load on the machine whose decision latency Chapter 7 reports, making the measurement partly a function of how many dashboard panels were open. Separating the monitoring host keeps the machine under measurement quiet.

---

## Files

### prometheus.yml
The scrape configuration. Place at `/etc/prometheus/prometheus.yml`, set ownership to `prometheus:prometheus`, validate with `promtool check config`, and restart the service.

### grafana-dashboard-zt.json
The dashboard definition, importable through Grafana's dashboard import (Dashboards, New, Import, then paste the JSON model). A template variable filters to one telemetry mode, which is how the three modes are compared visually.

Seven panels: mode coverage, decisions by mode and action, ALLOW against DENY totals, mean and p95 latency by mode and phase, revocation cost, protocol events, and rejections by reason.

---

## Revision 2026-08-11, and the reading of the dashboard that prompted it

Three defects were found by reading the deployed dashboard against the code that fed it. Each one is worth recording, because in every case the dashboard looked healthy while showing something misleading.

**The decision counter mixed decisions with bookkeeping.** `zt_decisions_total` carried five action values: ALLOW, DENY and REJECT, plus EVAL, the homomorphic round-one record written before any decision exists, and EXPIRE, the reaper's record. Every homomorphic cycle emits one EVAL *and* one ALLOW or DENY, so the two-round mode showed roughly twice the decision count of baseline purely because its protocol has two rounds. Any cross-mode comparison drawn from that panel would have been wrong in a way that flattered nothing and confused everything. Bookkeeping now goes to `zt_protocol_events_total`.

**The exporter served a frozen snapshot.** `metrics_exporter.py` builds one `MeasurementLogger` at process start, and that object replayed the logs exactly once. Nothing re-read them. The signature on the dashboard was flat horizontal lines that stepped only when the service was restarted, which is easy to mistake for a quiet system. `measurement.py` now tails both logs from a stored byte offset and refreshes before every exposition, so the panels advance live.

**The reaper reported a latency of zero.** The expiry record hardcoded `latency_ms: 0.0`, so the expiry series could never show anything real, while expiry revocation is exactly the path the ~150 s worst-case bound describes. The reaper now measures its own teardown and also records `overdue_s`, the interval by which a session outlived its expiry before being swept. That second figure is what turns the 150 s bound from arithmetic into an observed quantity.

A fourth change is preventive rather than corrective. The dashboard's top panel now reports **mode coverage**, and turns red for any telemetry mode with no data. The campaign that produced the dashboard under review had been run in homomorphic mode alone, and nothing on the dashboard said so. The cross-mode comparison is the core claim of the thesis, and a missing mode should be the first thing visible rather than something inferred from a legend.

Rejections also carry a `reason` label now. A rejection count without a reason cannot be acted on: a replayed nonce that the system refuses is a defence working correctly, while a report refused for a timestamp outside the freshness window is clock skew on the sending machine and invalidates the repetitions around it. Those two need to be distinguishable at a glance.

---

## Bring-up, and the faults it produced

This machine was the last to come onto the laboratory segments and produced several faults worth recording, all of which appear in the Chapter 5 fault log.

**Laboratory address on a bridged adapter.** The static address looked correct while the gateway stayed unreachable. The giveaway was a public IPv6 address from the site router on the same interface, which no host-only segment can issue. Same signature as the Client B fault, and the reason `accept-ra: false` now appears in this machine's netplan.

**Two configuration systems managing one interface.** Ubuntu Desktop defaults netplan's renderer to NetworkManager, and static addresses set through the desktop settings dialogue were written to `90-NM-*.yaml` files that sort after, and therefore override, the project's `60-zt-monitoring.yaml`. The address kept reverting. Resolved by pinning `renderer: networkd` and setting the interfaces unmanaged in NetworkManager.

**One-way ARP across the virtual switch.** The hardest of the three. The PDP could ping this host and unicast traffic passed in both directions, but this host's ARP requests for the PDP went unanswered, so connections initiated from here timed out while everything else looked correct. Every layer checked out: the firewall counted and accepted the packets, the return route was right, and the exporter answered locally. Diagnosed by noticing that the connection succeeded only while the neighbour cache had been refreshed by inbound traffic. Worked around with a permanent neighbour entry.

```bash
sudo ip neigh replace 192.168.10.1 lladdr <PDP ens33 MAC> dev ens34 nud permanent
```

The general lesson matches the earlier interface faults: when every layer verifies correct and traffic still fails, suspect the layer below the one being configured.

---

## Verification

```bash
curl -s http://192.168.10.1:8000/metrics | grep zt_    # exporter, from here
promtool check config /etc/prometheus/prometheus.yml
systemctl status prometheus grafana-server
```

Then open `http://192.168.10.50:9090/targets`; the `zt-pdp` job should read UP with a scrape duration in the tens of milliseconds. The Grafana dashboard is at `http://192.168.10.50:3000`.
