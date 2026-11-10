#!/usr/bin/env python3
"""
he_decrypt.py — client-side Paillier decryption of the PDP's HE answer.

Called by context_agent.ps1 after the PDP returns Enc(score - threshold)
(the 'enc_comparison' field from the server's evaluate_encrypted / he_finalise).
Loads the client's PRIVATE key, decrypts the comparison, and prints the
allow/deny decision. Only the client can do this, because only the client
holds the private key — the PDP never learns the score.

Decision rule (matches the server: enc_total = sum - THRESHOLD):
    decrypted >= 0  ->  score was >= threshold  ->  DENY
    decrypted <  0  ->  score was <  threshold  ->  ALLOW

Usage (the agent does this for you):
    echo '{"enc_comparison":"{\"v\":\"...\",\"e\":0}","pub_key_n":"..."}' | python he_decrypt.py
"""
import json
import sys
from pathlib import Path

import phe as paillier

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scoring   # copied next to this file by install_agent.ps1 (Finding A)

KEY_FILE = Path(__file__).resolve().parent / "he_key.json"


def load_private_key():
    d = json.loads(KEY_FILE.read_text())
    pub = paillier.PaillierPublicKey(n=int(d["n"]))
    priv = paillier.PaillierPrivateKey(pub, int(d["p"]), int(d["q"]))
    return pub, priv


def _des(s, pub):
    # MUST match server he_risk_engine.py._des exactly
    d = json.loads(s)
    return paillier.EncryptedNumber(pub, int(d["v"]), int(d["e"]))


def main():
    raw_text = sys.stdin.read().strip()
    payload = json.loads(raw_text) if raw_text else {}

    pub, priv = load_private_key()

    enc_cmp = _des(payload["enc_comparison"], pub)
    diff = priv.decrypt(enc_cmp)          # = score - threshold

    decision = "DENY" if diff >= 0 else "ALLOW"
    score = diff + scoring.THRESHOLD      # reconstruct the score (single source
                                          # of truth — review Finding A)

    sys.stdout.write(json.dumps({
        "action": decision,
        "score": score,
        "margin": diff,                   # how far over/under the threshold
    }))


if __name__ == "__main__":
    main()
