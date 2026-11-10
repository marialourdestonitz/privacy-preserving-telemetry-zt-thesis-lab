# Machine 1: zt-pdp-server (Ubuntu 24.04 LTS)

This machine hosts both the Policy Decision Point and the Policy Enforcement Point. It terminates mutual TLS for all telemetry, owns the WireGuard tunnel, holds the certificate authority, and serves as the laboratory time source.

**Addresses:** 192.168.10.1, 192.168.20.1, 192.168.30.1, 192.168.40.1; tunnel 10.0.0.1

**Deployed to:** `/opt/zt-thesis/pdp/` (source kept in `/root/zt-enterprise/`)

---

## pdp/ (the running service)

### pdp_server.py
The Policy Decision Point itself, a FastAPI service under Uvicorn terminating mutual TLS on port 8443. It is the entry point for every telemetry report and the place where a decision becomes a session.

What it does per request: validates the report against a strict Pydantic schema (rejecting anything that is not a decision-relevant claim), enforces the 30-second freshness window and the per-message nonce that together defeat replay, routes the report by mode, obtains a decision, records a session bound to the client's tunnel address, calls the enforcement layer, and writes the decision record.

It also runs a background reaper that sweeps every 30 seconds and tears down sessions past their 120-second time to live, which is what makes trust expire on its own.

Endpoints: `/api/v1/telemetry` (all modes), `/api/v1/he_decision` (round two of the homomorphic protocol), `/api/v1/revoke`, `/api/v1/sessions`, `/api/v1/salt/material`, `/api/v1/health`.

### scoring.py
The trust algorithm, and the single source of truth for every weight and the threshold. Both the server and the clients import it, which is the reason the three telemetry modes cannot disagree.

It converts posture claims into a risk score: remote zone adds 30, no disk encryption 20, stale patches 15 or 25, failed logons 15 or 25, logon anomaly 10, no domain membership 10, no Secure Boot 10. A total of 60 or more yields DENY; anything below yields ALLOW.

### test_scoring_parity.py
Proves the claim the thesis depends on. It generates twenty thousand random postures plus the corner cases of the evaluation scenarios, runs each through the baseline, pseudonymised, and homomorphic paths, and asserts that all three return identical decisions. If this test fails, no comparison between modes is meaningful.

### he_risk_engine.py
The homomorphic risk engine. It performs the same arithmetic as `scoring.py` but over Paillier ciphertext, computing Enc(sum of sub-scores − 60) without decrypting anything. The additive structure of the trust algorithm is what makes a partially homomorphic scheme sufficient here; had the algorithm required multiplication, the far heavier machinery of fully homomorphic encryption would have been needed.

### privacy_transform.py
The pseudonymisation layer for hmac mode, and the identifier guard for all modes. It replaces device identifiers with salted-HMAC pseudonyms under a rotating salt, and it walks incoming claim dictionaries recursively to reject any raw identifier that slipped past schema validation. This is the code that operationalises data minimisation.

### pep_manager.py
The Policy Enforcement Point. It contains no scoring logic; it receives a decision and turns it into network state across three layers under a single lock:

1. WireGuard peer admission on `wg-zt0`, binding the peer public key to exactly its tunnel address.
2. Per-scope iptables ACCEPT rules over a default-deny forwarding policy: SMB reaches 192.168.30.0/24 port 445, S3 reaches 192.168.40.0/24 ports 9000 and 9001.
3. Object-store credential lifecycle, minting a random per-device key on ALLOW and revoking it on DENY.

Posture-driven DENY, session expiry, and explicit revocation all call the same teardown path, so no plane can stay open while another closes.

### measurement.py
The evaluation instrumentation. Every decision is logged with its mode, action, score, scope, tunnel address, and a phase-tagged latency, which is what allows the homomorphic evaluation cost to be reported separately from enforcement time.

### metrics_exporter.py
Publishes aggregate-only metrics on port 8000 for Prometheus: decision counters by mode and action, and mean and p95 latency by mode and phase. No per-device series ever leaves this machine, which is what keeps observability from reintroducing the exposure the design removes.

### run_experiment.py
The campaign orchestrator. It replays the evaluation scenarios across modes and repetitions so the Chapter 7 tables can be produced reproducibly rather than by hand.

### zt-pdp.service, zt-metrics.service
The systemd units. The PDP unit pins `ZT_WG_IFACE=wg-zt0` and `ZT_LOG_DIR=/var/log/zt-thesis` and orders itself after the tunnel; forgetting those variables was the cause of an early fault in which decisions were made but nothing was enforced. It runs a single worker on purpose, because the session store lives in process memory and multiple workers would each hold a different view of it.

### requirements.txt
Pinned dependency versions, so the system that is measured is the system that is reported.

---

## setup/ (the build scripts)

### setup_interfaces.sh
Maps the machine's real NIC names to the laboratory segments through netplan. It prints the live interface list, requires the operator to confirm the mapping, and applies changes with auto-revert so a mistake cannot cause lockout over SSH. Hypervisors name NICs by adapter order, so hard-coding those names across machines does not survive a rebuild.

### setup_certs.sh
Generates the project certificate authority, the PDP server certificate with the PDP addresses in the subject alternative name, and the client PKCS#12 bundles. Trust is CA-based rather than thumbprint-based, so a client certificate can be re-issued without touching the PDP.

### install_pdp.sh
The idempotent installer, which matters because it is re-run on every code update. It installs packages, builds the virtual environment from the pinned requirements, generates the WireGuard server key only if none exists (regenerating it would invalidate every client), writes the tunnel configuration with default-deny forwarding installed through PostUp hooks, enables IP forwarding, creates the secrets file on first run at mode 0600, copies the code into the deploy target, and installs the systemd unit. It ends by printing the forwarding policy and the server public key.
