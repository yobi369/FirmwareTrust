from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA_VERSION = "1.0"
SIGNATURE_ALGORITHM = "Ed25519"
DIGEST_ALGORITHM = "sha256"


class FirmwareTrustError(Exception):
    """Base exception for expected FirmwareTrust failures."""


class VerificationError(FirmwareTrustError):
    """Raised when an artifact or signed manifest cannot be verified."""


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def canonical_manifest_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (ValueError, TypeError) as exc:
        raise FirmwareTrustError(f"Unable to load unencrypted PEM private key: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise FirmwareTrustError("Private key must be Ed25519.")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (ValueError, TypeError) as exc:
        raise FirmwareTrustError(f"Unable to load PEM public key: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise FirmwareTrustError("Public key must be Ed25519.")
    return key


def key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def generate_key_pair(private_path: Path, public_path: Path) -> str:
    if private_path.resolve() == public_path.resolve():
        raise FirmwareTrustError("Private and public key paths must be different.")
    if private_path.exists() or public_path.exists():
        raise FirmwareTrustError("Refusing to overwrite an existing key file.")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_path.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    try:
        public_path.write_bytes(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    except OSError:
        private_path.unlink(missing_ok=True)
        raise
    try:
        private_path.chmod(0o600)
    except OSError:
        pass
    return key_id(public_key)


def sign_firmware(
    firmware_path: Path, private_key_path: Path, manifest_path: Path
) -> dict[str, Any]:
    if not firmware_path.is_file():
        raise FirmwareTrustError(f"Firmware file does not exist: {firmware_path}")
    if manifest_path.exists():
        raise FirmwareTrustError(f"Refusing to overwrite manifest: {manifest_path}")
    private_key = load_private_key(private_key_path)
    public_key = private_key.public_key()
    digest, size = sha256_file(firmware_path)
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "artifact": {
            "filename": firmware_path.name,
            "size_bytes": size,
            "digest_algorithm": DIGEST_ALGORITHM,
            "digest": digest,
        },
        "signature": {"algorithm": SIGNATURE_ALGORITHM, "key_id": key_id(public_key)},
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    signature = private_key.sign(canonical_manifest_bytes(payload))
    document = {
        **payload,
        "signature": {
            **payload["signature"],
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return document


def verify_firmware(
    firmware_path: Path, manifest_path: Path, trusted_public_key_path: Path
) -> dict[str, Any]:
    if not firmware_path.is_file():
        raise VerificationError(f"Firmware file does not exist: {firmware_path}")
    if not manifest_path.is_file():
        raise VerificationError(f"Manifest file does not exist: {manifest_path}")
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        artifact = document["artifact"]
        signature_info = document["signature"]
        signature_value = signature_info["value"]
        schema_version = document["schema_version"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise VerificationError(f"Malformed manifest: {exc}") from exc
    if not isinstance(artifact, dict) or not isinstance(signature_info, dict):
        raise VerificationError("Malformed manifest: artifact and signature must be objects.")
    if schema_version != SCHEMA_VERSION:
        raise VerificationError(f"Unsupported schema version: {schema_version}")
    if artifact.get("digest_algorithm") != DIGEST_ALGORITHM:
        raise VerificationError("Unsupported digest algorithm.")
    if signature_info.get("algorithm") != SIGNATURE_ALGORITHM:
        raise VerificationError("Unsupported signature algorithm.")
    trusted_key = load_public_key(trusted_public_key_path)
    if signature_info.get("key_id") != key_id(trusted_key):
        raise VerificationError("Manifest key ID does not match the trusted public key.")
    actual_digest, actual_size = sha256_file(firmware_path)
    if artifact.get("digest") != actual_digest:
        raise VerificationError("Firmware SHA-256 digest mismatch.")
    if artifact.get("size_bytes") != actual_size:
        raise VerificationError("Firmware size mismatch.")
    signed_payload = {key: value for key, value in document.items() if key != "signature"}
    signed_payload["signature"] = {
        "algorithm": signature_info["algorithm"],
        "key_id": signature_info["key_id"],
    }
    try:
        signature = base64.b64decode(signature_value, validate=True)
        trusted_key.verify(signature, canonical_manifest_bytes(signed_payload))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise VerificationError("Manifest signature is invalid.") from exc
    return {
        "verified": True,
        "artifact": firmware_path.name,
        "sha256": actual_digest,
        "size_bytes": actual_size,
        "key_id": key_id(trusted_key),
        "signature_algorithm": SIGNATURE_ALGORITHM,
    }
