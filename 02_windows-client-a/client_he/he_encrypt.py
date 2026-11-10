#!/usr/bin/env python3

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
        # no-op on Windows; installer sets the ACLs to allow only the current user to read/write the file. On Linux, chmod 600 is sufficient.
        os.chmod(KEY_FILE, 0o600)   
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
    # canonical scoring of the raw posture, then encrypt each sub-score under the client's Paillier public key
    subs = scoring.subscores_from_posture(raw)   

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
