# Machine 5: ubuntu-cloud (MinIO object store)

The cloud plane of the protected file sharing. MinIO provides an S3-compatible
object store over TLS, and like the SMB server it runs no project code: the PDP
decides and the PEP enforces, from outside.

**Address:** 192.168.40.10 on the cloud segment
**S3 API:** port 9000 over TLS · **Console:** port 9001
**Certificates:** `/etc/minio/certs/`
**Buckets:** `zt-bucket`, `enterprise-objects`

---

## How enforcement reaches this machine

The cloud plane is gated twice, and both gates are operated by the PEP on the PDP.

The first gate is the network: iptables rules for the s3 scope open ports 9000
and 9001 to the client's tunnel address only while an ALLOW holds.

The second gate is credentials: on ALLOW the PEP mints a random per-device
access key through MinIO's administrative API and the `mc` client, named after
the client's tunnel address (for example `zt-device-10-0-0-2`), attaches the
`readwrite` policy to it, and delivers the key to the client inside the same
mutually authenticated response. On DENY that user is removed. A client that
somehow retained network reachability would therefore still hold a dead
credential.

This double gating is why the S3 evidence is the strongest demonstration in the
evaluation: `mc admin user list myminio` shows the device user appearing and
disappearing in step with the policy decision, which is visible proof that a
cloud service was severed by a posture change.

---

## setup/ (the build scripts)

### setup_minio.sh
The idempotent installer for this machine. It installs the `minio` and `mc`
binaries, creates the service account and data directory, generates the admin
credential on first run only, issues a TLS certificate from the laboratory CA
with the machine's address in the subject alternative name, installs the
systemd unit, and creates the two buckets. It ends by printing the exact three
lines that must be copied into `/etc/zt-thesis/pdp.env` on the PDP.

The credential is generated once and preserved on re-runs. Regenerating it
would break every PDP that had it configured, which is the same class of fault
as the WireGuard key regeneration recorded as E1 and the credential divergence
recorded as E8.

### minio.service
The systemd unit. Both ports are pinned as literal arguments in `ExecStart`
rather than expanded from an options variable, because systemd does not perform
shell word splitting there. Passing them through a variable left the console
binding a different port after every restart, the fault recorded as E7.

### verify_minio.sh
Evidence collection for the documentation. It prints the segment address, the
service state, the listening ports, the certificate subject and validity, the
bucket list, and the device users currently issued by the PEP. Every one of
those outputs belongs in the implementation chapter as a screenshot.

---

## The four values that must agree with the PDP

The PEP drives this machine through `mc`, so four settings must line up. The
PDP's environment file is the authoritative source; a divergence here produces
authentication failures during credential issuance that look like a PEP bug but
are a configuration mismatch.

| Setting on the PDP | Value | Set here by |
|---|---|---|
| `ZT_MINIO_URL` | `https://192.168.40.10:9000` | the address and port in `minio.service` |
| `ZT_MINIO_ADMIN_USER` | `admin` | `MINIO_ROOT_USER` in `/etc/minio/admin.env` |
| `ZT_MINIO_ADMIN_PASS` | generated on first run | `MINIO_ROOT_PASSWORD` in the same file |
| `ZT_MINIO_ALIAS` | `myminio` | the alias `setup_minio.sh` configures |

**One mismatch to check before the evaluation campaign.** The default in
`pep_manager.py` is `http://192.168.40.10:9000`, while the Windows agent writes
`https://192.168.40.10:9000` into `s3-credentials.txt` and this machine serves
TLS. Set `ZT_MINIO_URL` explicitly to the `https` form in `pdp.env` rather than
relying on the default, or credential issuance will attempt plain HTTP against
a TLS listener.

---

## Verification commands

```bash
bash setup/verify_minio.sh          # everything at once
```

Or individually:

```bash
ip -br addr | grep 192.168.40
systemctl status minio
sudo ss -tlnp | grep -E "9000|9001"
sudo openssl x509 -in /etc/minio/certs/public.crt -noout -subject -dates
mc ls myminio
mc admin user list myminio
```

---

## superseded/

This subfolder held the REST and WebDAV resource-server code from an earlier,
wider scope. That material now lives in `09_superseded/rest-webdav-planes/`.
The copy in this folder can be deleted; it is a duplicate.
