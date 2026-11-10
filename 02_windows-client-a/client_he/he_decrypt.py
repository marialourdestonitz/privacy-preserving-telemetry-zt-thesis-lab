#!/usr/bin/env python3

import json
import sys
from pathlib import Path

import phe as paillier

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scoring 

KEY_FILE = Path(__file__).resolve().parent / "he_key.json"


def load_private_key():
    d = json.loads(KEY_FILE.read_text())
    pub = paillier.PaillierPublicKey(n=int(d["n"]))
    priv = paillier.PaillierPrivateKey(pub, int(d["p"]), int(d["q"]))
    return pub, priv


def _des(s, pub):
    # MUST match server he_risk_engine.py. 
    d = json.loads(s)
    return paillier.EncryptedNumber(pub, int(d["v"]), int(d["e"]))


def main():
    raw_text = sys.stdin.read().strip()
    payload = json.loads(raw_text) if raw_text else {}

    pub, priv = load_private_key()

    enc_cmp = _des(payload["enc_comparison"], pub)
    diff = priv.decrypt(enc_cmp)       

    decision = "DENY" if diff >= 0 else "ALLOW"
    score = diff + scoring.THRESHOLD     
                                         

    sys.stdout.write(json.dumps({
        "action": decision,
        "score": score,
        # how far over/under the threshold
        "margin": diff,                   
    }))


if __name__ == "__main__":
    main()
