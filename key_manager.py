"""PBKDF2-похідна ключів, metadata-only keystore, ротація та облік використань."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from config import ITERATIONS, MAX_ENCRYPTIONS, MAX_KEY_AGE_DAYS, SALT_BYTES


class KeyManagementError(ValueError):
    pass


class InvalidPassword(KeyManagementError):
    pass


def _write_private_json(path: Path, db: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".keys-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(db, out, ensure_ascii=False, indent=2)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def _derive(password: str, salt: bytes, iterations: int, key_bits: int) -> tuple[bytes, bytes, bytes]:
    if not password:
        raise InvalidPassword("Password is required")
    if len(salt) != SALT_BYTES or iterations < ITERATIONS or key_bits not in (128, 192, 256):
        raise KeyManagementError("Invalid key derivation settings")
    length = key_bits // 8 + 64
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=length, salt=salt, iterations=iterations
    )
    material = kdf.derive(password.encode("utf-8"))
    n = key_bits // 8
    return material[:n], material[n:n + 32], material[n + 32:]


def _proof(check_key: bytes, key_id: str) -> str:
    return hmac.new(check_key, b"ALAB-key-proof-v2:" + key_id.encode("ascii"), hashlib.sha256).hexdigest()


class KeyManager:
    def __init__(self, path: str | Path = ".aes-lab/keystore.json"):
        self.path = Path(path)
        if self.path.exists():
            if not self.path.is_file():
                raise KeyManagementError("Keystore is not a regular file")
            self.db = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(self.db, dict) or not isinstance(self.db.get("keys"), list):
                raise KeyManagementError("Malformed keystore")
        else:
            self.db = {"format": 2, "keys": []}

    def _save(self) -> None:
        _write_private_json(self.path, self.db)

    def list_keys(self) -> list[dict[str, Any]]:
        return [
            {k: rec[k] for k in ("label", "key_id", "key_bits", "created_at", "uses", "status")}
            for rec in self.db["keys"]
        ]

    def _active(self, label: str) -> dict[str, Any]:
        matches = [k for k in self.db["keys"] if k["label"] == label and k["status"] == "active"]
        if len(matches) != 1:
            raise KeyManagementError("Active key label not found or ambiguous")
        return matches[0]

    def get_by_id(self, key_id: str) -> dict[str, Any]:
        matches = [k for k in self.db["keys"] if k["key_id"] == key_id]
        if len(matches) != 1:
            raise KeyManagementError("Unknown key identifier")
        return matches[0]

    def new_key(self, label: str, password: str, key_bits: int = 256, *, retire: bool = False) -> dict[str, Any]:
        if not label or len(label) > 60 or not all(c.isalnum() or c in "_-" for c in label):
            raise KeyManagementError("Label must contain 1..60 letters, digits, '-' or '_'")
        if len(password) < 12:
            raise KeyManagementError("Passphrase must have at least 12 characters")
        if key_bits not in (128, 192, 256):
            raise KeyManagementError("AES key size must be 128/192/256 bits")
        actives = [k for k in self.db["keys"] if k["label"] == label and k["status"] == "active"]
        if actives and not retire:
            raise KeyManagementError("Active label exists; use key rotate")
        key_id = secrets.token_hex(12)
        salt = secrets.token_bytes(SALT_BYTES)
        _, _, check_key = _derive(password, salt, ITERATIONS, key_bits)
        rec = {
            "label": label, "key_id": key_id, "salt": salt.hex(), "iterations": ITERATIONS,
            "kdf": "PBKDF2-HMAC-SHA256", "key_bits": key_bits,
            "proof": _proof(check_key, key_id), "created_at": int(time.time()),
            "uses": 0, "status": "active",
        }
        if retire:
            for old in actives:
                old["status"] = "retired"
        self.db["keys"].append(rec)
        self._save()
        return rec

    def keys_for(self, rec: dict[str, Any], password: str) -> tuple[bytes, bytes]:
        if rec["kdf"] != "PBKDF2-HMAC-SHA256":
            raise KeyManagementError("Unsupported KDF")
        a, m, proof_key = _derive(password, bytes.fromhex(rec["salt"]), int(rec["iterations"]), int(rec["key_bits"]))
        if not hmac.compare_digest(_proof(proof_key, rec["key_id"]), rec["proof"]):
            raise InvalidPassword("Wrong password")
        return a, m

    def active_keys(self, label: str, password: str) -> tuple[dict[str, Any], bytes, bytes]:
        rec = self._active(label)
        if rec["uses"] >= MAX_ENCRYPTIONS:
            raise KeyManagementError("Usage limit reached. Rotate key before encrypting again")
        if time.time() - rec["created_at"] > MAX_KEY_AGE_DAYS * 86400:
            raise KeyManagementError("Key age limit reached. Rotate key")
        return rec, *self.keys_for(rec, password)

    def rotate(self, label: str, password: str, key_bits: int | None = None) -> dict[str, Any]:
        current = self._active(label)
        self.keys_for(current, password)  # existing passphrase authentication required
        return self.new_key(label, password, key_bits or current["key_bits"], retire=True)

    def record_use(self, key_id: str) -> None:
        rec = self.get_by_id(key_id)
        if rec["status"] != "active":
            raise KeyManagementError("Cannot encrypt with retired key")
        rec["uses"] += 1
        self._save()
