"""
privacy_transform.py — pseudonymisation + minimisation for hmac mode.

REVISED per the implementation review 2026-07:
  Finding D: get_salt_material() added — the PDP now provisions the real
             rotating salt to authenticated clients over mTLS
             (/api/v1/salt/material), so device_id_hmac is a keyed
             HMAC-SHA256 pseudonym instead of a date-keyed hash.
  Finding A: transform() now emits the canonical minimised claim set from
             scoring.claims_from_posture(), so the server-side reference
             transform and the agent's Build-HmacClaims stay in lock-step.
  Hygiene:   unused imports removed; claim key renamed device_id ->
             device_id_hmac to match the wire schema (HMACClaims).
"""
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import scoring


class PrivacyTransform:
    # Raw identifier fields that must NEVER appear in pseudonymised (HMAC) mode.
    FORBIDDEN_KEYS = {
        "hostname", "host_name", "mac", "mac_address", "ip", "ip_address",
        "username", "user", "sid", "serial", "serial_number", "fqdn",
    }

    def __init__(self, rotation_hours=24,
                 salt_store="/var/lib/zt-thesis/salt"):
        self.rotation_hours = rotation_hours
        self.salt_store     = Path(salt_store)
        self.salt_store.parent.mkdir(parents=True, exist_ok=True)
        self._salt          = b""
        self._salt_created  = datetime.min.replace(tzinfo=timezone.utc)
        self._ensure_salt()

    def _ensure_salt(self):
        if self.salt_store.exists():
            try:
                data    = json.loads(self.salt_store.read_text())
                created = datetime.fromisoformat(data["created"])
                age_h   = (datetime.now(timezone.utc) - created
                           ).total_seconds() / 3600
                if age_h < self.rotation_hours:
                    self._salt         = bytes.fromhex(data["salt"])
                    self._salt_created = created
                    return
            except Exception:
                pass
        self._rotate_salt()

    def _rotate_salt(self):
        self._salt         = secrets.token_bytes(32)
        self._salt_created = datetime.now(timezone.utc)
        self.salt_store.write_text(json.dumps({
            "salt":    self._salt.hex(),
            "created": self._salt_created.isoformat(),
        }))
        try:
            self.salt_store.chmod(0o600)
        except OSError:
            pass

    def get_current_salt_hash(self):
        self._ensure_salt()
        return hashlib.sha256(self._salt).hexdigest()

    def get_salt_material(self):
        """The actual salt (hex), for authenticated clients only — served
        exclusively via the PDP's mTLS listener (Finding D). Rotates on the
        configured cadence; clients should re-fetch when the fingerprint
        from /api/v1/salt changes or once per cycle."""
        self._ensure_salt()
        return self._salt.hex()

    def salt_expires_at(self):
        self._ensure_salt()
        return self._salt_created + timedelta(hours=self.rotation_hours)

    # ----------------------------------------------------------------------
    # Privacy contract enforcement: reject any raw identifier in HMAC mode.
    # Recurses through nested dicts/lists so an identifier cannot be smuggled
    # inside a sub-object. Returns True if a forbidden identifier is present.
    # ----------------------------------------------------------------------
    def contains_identifier(self, payload):
        if isinstance(payload, dict):
            for k, v in payload.items():
                if k.lower() in self.FORBIDDEN_KEYS and v not in (None, "", []):
                    return True
                if self.contains_identifier(v):
                    return True
        elif isinstance(payload, list):
            for item in payload:
                if self.contains_identifier(item):
                    return True
        return False

    def pseudonymise(self, identifier):
        self._ensure_salt()
        h = hmac.new(self._salt, identifier.encode(), hashlib.sha256)
        return h.hexdigest()[:16]

    def transform(self, baseline):
        """Reference transform raw posture -> wire claims (mirrors the agent's
        Build-HmacClaims; used by tests and the experiment orchestrator)."""
        claims = scoring.claims_from_posture(baseline)
        claims["device_id_hmac"] = self.pseudonymise(
            baseline.get("hostname", "") + baseline.get("mac_address", ""))
        return claims
