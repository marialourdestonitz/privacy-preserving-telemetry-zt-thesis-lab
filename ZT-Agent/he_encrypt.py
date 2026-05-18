#!/usr/bin/env python3


import os, json, sys
from pathlib import Path
from phe import paillier

# Paths — kept in sync with context_agent.ps1
INPUT_PATH   = Path(r"C:\ProgramData\ZT-Agent\he_input.json")
KEYS_DIR     = Path(r"C:\ProgramData\ZT-Agent\he_keys")
PRIVKEY_PATH = KEYS_DIR / "paillier_priv.json"
PUBKEY_PATH  = KEYS_DIR / "paillier_pub.json"

KEY_SIZE = 2048


def load_or_create_keypair():
    """Load persistent keypair, or generate one on first run."""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    if PRIVKEY_PATH.exists() and PUBKEY_PATH.exists():
        with open(PUBKEY_PATH) as f:
            pub_data = json.load(f)
        with open(PRIVKEY_PATH) as f:
            priv_data = json.load(f)
        pub = paillier.PaillierPublicKey(n=int(pub_data["n"]))
        priv = paillier.PaillierPrivateKey(pub,
                                           int(priv_data["p"]),
                                           int(priv_data["q"]))
        return pub, priv

    # First run: generate a fresh keypair
    pub, priv = paillier.generate_paillier_keypair(n_length=KEY_SIZE)
    with open(PUBKEY_PATH, "w") as f:
        json.dump({"n": str(pub.n)}, f)
    with open(PRIVKEY_PATH, "w") as f:
        json.dump({"p": str(priv.p), "q": str(priv.q)}, f)
    return pub, priv


def z_score(raw):
    """Zone risk: 0=trusted, 30=internal, 50=public."""
    zone = (raw.get("zone") or "").lower()
    if zone == "trusted":
        return 0
    if zone in ("internal", "corporate", "protected"):
        return 30
    return 50


def p_score(raw):
    """Posture: 0 if all checks pass, 35 otherwise."""
    ok = (raw.get("disk_encrypted") and
          (raw.get("patch_age_days", 999) < 30) and
          raw.get("domain_joined"))
    return 0 if ok else 35


def l_score(raw):
    """Login burst indicator: 0 if quiet, 20 if many failed logins."""
    return 0 if raw.get("failed_logins", 0) <= 3 else 20


def serialise(c):
    """Convert a Paillier ciphertext to a dict suitable for JSON transport."""
    return {"ciphertext": str(c.ciphertext()), "exponent": c.exponent}


def main():
    with open(INPUT_PATH) as f:
        raw = json.load(f)

    pub, _ = load_or_create_keypair()

    out = {
        "mode":         "he",
        "enc_zone":     serialise(pub.encrypt(z_score(raw))),
        "enc_posture":  serialise(pub.encrypt(p_score(raw))),
        "enc_login":    serialise(pub.encrypt(l_score(raw))),
        "pub_key_n":    str(pub.n),
        "tunnel_ip":    raw.get("tunnel_ip"),
        "wg_pubkey":    raw.get("wg_pubkey"),
        "requested_resources": raw.get("requested_resources", []),
        "timestamp":    raw.get("timestamp"),
    }
    print(json.dumps(out))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)