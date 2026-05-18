#!/usr/bin/env python3

import json
from pathlib import Path
from phe import paillier

INPUT_PATH   = Path(r"C:\ProgramData\ZT-Agent\he_response.json")
KEYS_DIR     = Path(r"C:\ProgramData\ZT-Agent\he_keys")
PRIVKEY_PATH = KEYS_DIR / "paillier_priv.json"
PUBKEY_PATH  = KEYS_DIR / "paillier_pub.json"


def load_keypair():
    with open(PUBKEY_PATH) as f:
        pub_data = json.load(f)
    with open(PRIVKEY_PATH) as f:
        priv_data = json.load(f)
    pub = paillier.PaillierPublicKey(n=int(pub_data["n"]))
    priv = paillier.PaillierPrivateKey(pub,
                                       int(priv_data["p"]),
                                       int(priv_data["q"]))
    return pub, priv


def deserialise(d, pub):
    return paillier.EncryptedNumber(pub,
                                    int(d["ciphertext"]),
                                    d.get("exponent", 0))


def main():
    with open(INPUT_PATH) as f:
        resp = json.load(f)

    pub, priv = load_keypair()
    enc_diff = deserialise(resp["enc_comparison"], pub)
    diff = priv.decrypt(enc_diff)
    # Negative diff means total < threshold → ALLOW
    # Non-negative means total ≥ threshold → DENY
    print("ALLOW" if diff < 0 else "DENY")


if __name__ == "__main__":
    main()