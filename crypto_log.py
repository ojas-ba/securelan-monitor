import base64
import hashlib
import hmac
import json
import os
from typing import Any, Dict, List, Tuple

from cryptography.fernet import Fernet


def _canonical_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def load_or_create_fernet(key_path: str) -> Fernet:
    if os.path.exists(key_path):
        with open(key_path, "rb") as handle:
            key = handle.read().strip()
    else:
        key = Fernet.generate_key()
        with open(key_path, "wb") as handle:
            handle.write(key)
    return Fernet(key)


def load_or_create_hmac_secret(secret_path: str) -> bytes:
    if os.path.exists(secret_path):
        with open(secret_path, "rb") as handle:
            raw = handle.read().strip()
        try:
            return base64.urlsafe_b64decode(raw)
        except Exception:
            return raw

    secret = os.urandom(32)
    encoded = base64.urlsafe_b64encode(secret)
    with open(secret_path, "wb") as handle:
        handle.write(encoded)
    return secret


def encrypt_text(fernet: Fernet, plaintext: str) -> str:
    return fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_text(fernet: Fernet, encrypted_blob: str) -> str:
    return fernet.decrypt(encrypted_blob.encode("utf-8")).decode("utf-8")


def sign_command_hmac(command: str, secret: bytes) -> str:
    digest = hmac.new(secret, command.encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()


def compute_entry_hash(
    prev_hash: str,
    timestamp: str,
    action_type: str,
    description: str,
    encrypted_blob: str,
    hmac_sig: str,
) -> str:
    payload = "|".join(
        [
            prev_hash,
            timestamp,
            action_type,
            description,
            encrypted_blob,
            hmac_sig,
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_audit_values(
    fernet: Fernet,
    prev_hash: str,
    timestamp: str,
    action_type: str,
    description_data: Dict[str, Any],
    hmac_sig: str,
) -> Tuple[str, str, str]:
    description = _canonical_json(description_data)
    encrypted_blob = encrypt_text(fernet, description)
    entry_hash = compute_entry_hash(
        prev_hash=prev_hash,
        timestamp=timestamp,
        action_type=action_type,
        description=description,
        encrypted_blob=encrypted_blob,
        hmac_sig=hmac_sig,
    )
    return description, encrypted_blob, entry_hash


def verify_chain(rows: List[Dict[str, Any]]) -> Tuple[bool, str]:
    prev_expected = "GENESIS"

    for row in rows:
        prev_hash = row["prev_hash"]
        if prev_hash != prev_expected:
            return False, f"Broken prev_hash link at audit id={row['id']}"

        recomputed = compute_entry_hash(
            prev_hash=prev_hash,
            timestamp=row["timestamp"],
            action_type=row["action_type"],
            description=row["description"],
            encrypted_blob=row["encrypted_blob"],
            hmac_sig=row["hmac_sig"],
        )

        if recomputed != row["entry_hash"]:
            return False, f"Entry hash mismatch at audit id={row['id']}"

        prev_expected = row["entry_hash"]

    return True, "Chain verified"
