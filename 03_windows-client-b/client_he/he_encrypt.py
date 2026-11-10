#!/usr/bin/env python3
"""
he_encrypt.py — client-side Paillier encryption for HE telemetry mode.

Called by context_agent.ps1 in 'he' mode. Reads raw posture as JSON on stdin,
generates (or reuses) the client's Paillier keypair, converts posture to the
four sub-scores, encrypts each under the client's PUBLIC key, and prints the
ciphertexts + public key as JSON on stdout.

The private key is saved locally (he_key.json) so he_decrypt.py can later
decrypt the PDP's encrypted answer. The PDP only ever sees the public key
and the ciphertexts — never the raw posture or the score.

Serialization MUST match the server's he_risk_engine.py:
    each ciphertext = {"v": str(ciphertext), "e": exponent}

REVISED per the implementation review 2026-07:
  Finding A: sub-scores now come from scoring.py — the SAME module the PDP
             uses. install_agent.ps1 copies scoring.py next to this file.
             No local weight table remains, so client and server can never
             drift apart.
  Hygiene:   he_key.json is written with owner-only permissions where the
             platform supports it (on Windows the installer sets the ACL).

Usage (the agent does this for you):
    echo '{"zone":"public","disk_encrypted":false,...}' | python he_encrypt.py
"""
import json
import os
import sys
from pathlib import Path

import phe as paillier

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scoring   # copied next to this file by install_agent.ps1

KEY_FILE = Path(__file__).resolve().parent / "he_key.json"


def load_or_create_keypair():
    """Reuse the client's keypair if present, else create and persist it."""
    if KEY_FILE.exists():
        try:
            d = json.loads(KEY_FILE.read_text())
            pub = paillier.PaillierPublicKey(n=int(d["n"]))
            priv = paillier.PaillierPrivateKey(pub, int(d["p"]), int(d["q"]))
            return pub, priv
        except Exception:
            pass  # fall through and regenerate if the file is bad
    pub, priv = paillier.generate_paillier_keypair(n_length=2048)
    KEY_FILE.write_text(json.dumps({
        "n": str(pub.n), "p": str(priv.p), "q": str(priv.q),
    }))
    try:
        os.chmod(KEY_FILE, 0o600)   # no-op on Windows; installer sets the ACL
    except OSError:
        pass
    return pub, priv


def _ser(enc):
    # MUST match server he_risk_engine.py._ser exactly
    return json.dumps({"v": str(enc.ciphertext()), "e": enc.exponent})


def main():
    raw_text = sys.stdin.read().strip()
    raw = json.loads(raw_text) if raw_text else {}

    pub, _ = load_or_create_keypair()
    subs = scoring.subscores_from_posture(raw)   # canonical (Finding A)

    out = {
        "enc_zone":    _ser(pub.encrypt(subs["zone"])),
        "enc_posture": _ser(pub.encrypt(subs["posture"])),
        "enc_patch":   _ser(pub.encrypt(subs["patch"])),
        "enc_login":   _ser(pub.encrypt(subs["login"])),
        "pub_key_n":   str(pub.n),
    }
    # single-line JSON so PowerShell's ConvertFrom-Json reads it cleanly
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
