# Machine 3: Windows Client B

The second endpoint, and the reason the micro-segmentation claim can be tested. It is enrolled exactly like Client A but granted only the SMB scope, so with the same class of certificate and an equally healthy posture it reaches the file share and is refused the object store.

**Tunnel address:** 10.0.0.3 · **Certificate:** client-b.pfx · **Scope:** smb only

**Segment address:** 192.168.20.20 on the untrusted client segment (gateway 192.168.20.1)

---

## The code is identical to Client A

`agent/` and `client_he/` contain the same files as `02_windows-client-a/`, and that is deliberate. Nothing about the software distinguishes the two machines. The difference lives entirely in the configuration and in what the PDP grants, which is what makes the comparison meaningful: if Client B could not reach the object store because it was running different code, the experiment would prove nothing about enforcement.

See `02_windows-client-a/README.md` for the description of each file.

---

## What differs: the configuration block

In `context_agent.ps1` on this machine:

```
$TELEMETRY_MODE      = 'he'
$PDP_URL             = 'https://192.168.20.1:8443/api/v1/telemetry'
$CLIENT_CERT_THUMB   = '<thumbprint of client-b.pfx>'
$REQUESTED_RESOURCES = @('smb')
$TUNNEL_IP           = '10.0.0.3'
```

Two values carry the experiment: `REQUESTED_RESOURCES` asks for the SMB scope only, and `TUNNEL_IP` identifies this client to the PDP. The tunnel address is the authoritative identity in this system, not the hostname or any label, because WireGuard binds a peer public key to exactly one tunnel address.

The PDP URL uses the address of the PDP on whichever segment this client sits.

---

## The verification that matters here

Client B's evidence is partly negative, which is unusual and worth capturing carefully. Both of the following must hold at the same time while the client holds an ALLOW:

```powershell
net use Z: \\192.168.30.10\ztshare /user:zauser *   # succeeds
Test-NetConnection 192.168.40.10 -Port 9000          # fails
```

The share connects because the PEP installed the rule for the smb scope. The object-store port stays closed because no rule was installed for a scope this client never requested and was never granted. That pair of results is the micro-segmentation scenario.

---

## Enrolment notes specific to this machine

The certificate and the CA are transferred from the PDP over SSH:

```powershell
scp zt-pdp-server@192.168.20.1:/tmp/ca.crt .
scp zt-pdp-server@192.168.20.1:/tmp/client-b.pfx .
Import-Certificate -FilePath .\ca.crt -CertStoreLocation Cert:\LocalMachine\Root
Import-PfxCertificate -FilePath .\client-b.pfx -CertStoreLocation Cert:\LocalMachine\My
```

One fault encountered while bringing this machine up is worth recording: the static laboratory address was initially configured on the bridged adapter rather than the host-only adapter connected to the laboratory segment. The symptom was an address that looked correct in the settings dialogue while the gateway remained unreachable, and the giveaway was a public IPv6 address on the same interface. The lesson matches the earlier interface-naming faults: confirm which adapter carries which network before assigning addresses, and remove bridged adapters from laboratory machines entirely, since they also place an "untrusted zone" client on the real network.
