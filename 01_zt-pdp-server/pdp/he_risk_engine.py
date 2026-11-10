#!/usr/bin/env python3

import json
import time

import scoring

try:
    import phe as paillier
    HE_AVAILABLE = True
except ImportError:
    HE_AVAILABLE = False


class HERiskEngine:

    THRESHOLD = scoring.THRESHOLD

    def generate_client_keypair(self):
        if not HE_AVAILABLE:
            raise RuntimeError("phe (python-paillier) not installed")
        return paillier.generate_paillier_keypair(n_length=2048)

    #encrypt
    def encrypt_telemetry(self, raw, public_key):
        """Reference client-side encryption (mirrors client_he/he_encrypt.py;
        used by tests and the experiment orchestrator). Sub-scores come from
        the canonical scorer, so sum(subscores) == baseline score exactly."""
        subs = scoring.subscores_from_posture(raw)
        return {
            "enc_zone":    self._ser(public_key.encrypt(subs["zone"])),
            "enc_posture": self._ser(public_key.encrypt(subs["posture"])),
            "enc_patch":   self._ser(public_key.encrypt(subs["patch"])),
            "enc_login":   self._ser(public_key.encrypt(subs["login"])),
            "pub_key_n":   str(public_key.n),
            "requested_resources": raw.get("requested_resources", []),
            "tunnel_ip":   raw.get("tunnel_ip"),
            "wg_pubkey":   raw.get("wg_pubkey"),
        }

    # evaluate
    def evaluate_encrypted(self, payload):
        t0  = time.perf_counter()
        pub = paillier.PaillierPublicKey(n=int(payload["pub_key_n"]))
        ez  = self._des(payload["enc_zone"], pub)
        ep  = self._des(payload["enc_posture"], pub)
        ea  = self._des(payload["enc_patch"], pub)
        el  = self._des(payload["enc_login"], pub)
        enc_total = ez + ep + ea + el - self.THRESHOLD
        return {
            "enc_comparison": self._ser(enc_total),
            "pub_key_n":      payload["pub_key_n"],
            "he_eval_ms":     round((time.perf_counter() - t0) * 1000, 3),
        }

    # serialisation
    def _ser(self, enc):
        return json.dumps({"v": str(enc.ciphertext()), "e": enc.exponent})

    def _des(self, s, pub):
        d = json.loads(s)
        return paillier.EncryptedNumber(pub, int(d["v"]), int(d["e"]))

