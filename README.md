# Laboratory Code, Organised by Virtual Machine

Maria Lourdes Tonitz · MSc Communication Engineering · FH Kärnten · July 2026

This folder holds every script the laboratory runs, filed under the machine that runs it, with an explanation of what each file does. It is a companion to `03_deployment_documentation/MT-Lab-Implementation-Master-by-VM.docx`, which describes the build procedure; this folder answers the different question of what the code itself does and why.

## Folder map

| Folder | Machine | What runs there |
|---|---|---|
| `01_zt-pdp-server/` | zt-pdp-server (Ubuntu 24.04) | Policy Decision Point, Policy Enforcement Point, setup scripts |
| `02_windows-client-a/` | Windows Client A (10.0.0.2) | Telemetry agent, client-side privacy transforms |
| `03_windows-client-b/` | Windows Client B (10.0.0.3) | Same code as Client A, different configuration |
| `04_windows-server-smb/` | Windows Server (192.168.30.10) | No custom code; configuration commands only |
| `05_ubuntu-cloud-minio/` | ubuntu-cloud (192.168.40.10) | MinIO service configuration; superseded REST and WebDAV code |
| `06_zt-monitoring/` | zt-monitoring (192.168.10.50) | Prometheus scrape config, Grafana dashboard |

## How the pieces fit together

One decision cycle touches four of these machines in order:

1. **Client A or B** collects device posture, applies the privacy transform for its mode, and submits the report over mutual TLS.
2. **zt-pdp-server** validates the report, runs the trust algorithm, and produces an ALLOW or DENY. In homomorphic mode it evaluates the comparison over ciphertext and never sees the score.
3. **zt-pdp-server** again, in its enforcement role, reconfigures the WireGuard peer, the per-scope firewall rules, and the object-store credentials.
4. **Windows Server** and **ubuntu-cloud** become reachable or unreachable as a result, without either of them running any policy logic.

The single most important property of the code layout is that the trust algorithm exists in exactly one file, `scoring.py`, which both the PDP and the clients use. That is why the three telemetry modes cannot drift apart, and `test_scoring_parity.py` proves it.

## Note on scope

The thesis evaluates two file-sharing planes, SMB and S3. Code for the earlier REST and WebDAV planes is preserved under `05_ubuntu-cloud-minio/superseded/` for completeness but is not part of the evaluated system and is never reached at runtime.
