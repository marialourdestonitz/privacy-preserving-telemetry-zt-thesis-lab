# Machine 4: Windows Server (SMB file share)

The on-premises plane of the protected file sharing. It holds the share and its local account and runs no project code at all, which is itself the point: whether a client can reach this machine is decided entirely by the PDP and enforced by the PEP on the network path, not by anything running here.

**Address:** 192.168.30.10 on the protected segment
**Share:** `\\192.168.30.10\ztshare`
**Local account:** `zauser`
**Port governed by the PEP:** 445

---

## Why there is no code in this folder

The design deliberately leaves the resource server unmodified. A conventional file server, with its ordinary share permissions and local accounts, sits behind the enforcement point and is protected without being aware of it. This matters for the thesis argument in two ways.

First, it shows the mechanism composes with existing infrastructure rather than replacing it. An enterprise does not have to modify its file servers to gain continuous verification.

Second, it locates the security boundary precisely. The share's own permissions still apply, but they are a second line: a client whose posture degrades loses network reachability to port 445 before its SMB credentials are ever presented. The two controls are independent and complementary.

---

## Configuration performed on this machine

Creating the share and the account, once:

```powershell
New-LocalUser -Name zauser -Password (Read-Host -AsSecureString) -PasswordNeverExpires
New-Item -Path C:\ZTShare -ItemType Directory
New-SmbShare -Name ztshare -Path C:\ZTShare -FullAccess zauser
```

Verification, for the documentation:

```powershell
Get-SmbShare
Get-SmbShareAccess -Name ztshare
Get-LocalUser zauser
Get-Service LanmanServer
ipconfig | findstr IPv4
```

---

## What the client does

On an allowed client the share is mapped as a network drive:

```powershell
net use Z: \\192.168.30.10\ztshare /user:zauser *
```

The instructive observation for the evaluation is what happens without any action on this server: when the client's decision flips to DENY, the PEP withdraws the rule for port 445 and drive Z: becomes unreachable within the revocation bound. The share still exists, the permissions are unchanged, and the account is still valid. Only the network path is gone. That separation between "who may in principle" and "who may right now" is the contribution the file server itself never has to know about.
