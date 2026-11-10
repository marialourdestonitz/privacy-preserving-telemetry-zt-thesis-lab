# Machine 2: Windows Client A

The primary endpoint. It holds both resource scopes, runs the telemetry agent on a 60-second cycle, and is the machine used for the employee-access demonstration.

**Tunnel address:** 10.0.0.2 · **Certificate:** client-a.pfx · **Scopes:** smb and s3

**Installed to:** `C:\ProgramData\ZT-Agent\` (staged from `C:\zt-setup\`)

---

## agent/

### context_agent.ps1
The telemetry agent, and the only component that sees the device's true posture. It runs as a SYSTEM scheduled task every 60 seconds and does four things per cycle.

First it collects the posture: disk encryption state (read with `manage-bde`, which is reliable under the SYSTEM account where `Get-BitLockerVolume` is not), operating-system patch age, failed logon count and logon anomaly, antivirus and firewall status, Secure Boot state, domain membership, uptime, and the network zone derived from the tunnel address.

Second it applies the privacy transform for its configured mode: nothing in baseline, salted-HMAC pseudonyms in hmac mode (fetching the current salt from the PDP), or Paillier encryption of four posture sub-scores in he mode.

Third it submits the report over mutual TLS with a fresh nonce and a current timestamp.

Fourth it acts on the response. In he mode this means decrypting only the sign of the returned comparison and posting the resulting verdict back for enforcement. When the response carries object-store credentials, it writes them to `s3-credentials.txt` for the user.

The agent is fail-closed by design: if it cannot reach the PDP or cannot build a valid request, it does not assume the previous ALLOW still holds. Access simply lapses when the session expires.

**Configuration block at the top of the file** (this is what differs between machines):

```
$TELEMETRY_MODE      = 'he'
$PDP_URL             = 'https://192.168.10.1:8443/api/v1/telemetry'
$CLIENT_CERT_THUMB   = '<thumbprint of client-a.pfx>'
$REQUESTED_RESOURCES = @('smb','s3')
$TUNNEL_IP           = '10.0.0.2'
```

### install_agent.ps1
Installs the agent: copies `context_agent.ps1` and the client-side crypto helpers into the agent directory, locks down the directory permissions so a standard user cannot alter what the agent reports, and registers the scheduled task to run as SYSTEM on a 60-second cycle.

### prepare-client.ps1
The posture readiness check, and the most useful diagnostic on this machine. Run without arguments it prints PASS or FAIL for each factor that feeds the trust algorithm, which lets you predict the score the PDP will produce before it produces it. Run with `-Fix` it remediates what it can, enabling BitLocker, Defender, and the firewall.

---

## client_he/

### he_encrypt.py
Encrypts the four posture sub-scores (zone, posture, patch, login) under the client's own Paillier public key and emits them with the public modulus. The key pair is generated on first run and stays on the client; the PDP never holds the private key, which is the entire basis of the privacy claim.

### he_decrypt.py
Decrypts the comparison the PDP returns and reads only its sign: negative means ALLOW, zero or positive means DENY. It deliberately does not expose the numeric value beyond what the verdict requires.

### scoring.py
A copy of the trust algorithm from the PDP. It is present so that the client computes its sub-scores with exactly the same weights the server uses. Keeping one authoritative file and copying it, rather than maintaining a second implementation, is what allows the parity test to pass.

---

## Note

The code in this folder is identical to Client B's. Only the configuration block differs, which is the point of the micro-segmentation scenario: same software, same posture logic, different granted scopes, and therefore different reachability.
