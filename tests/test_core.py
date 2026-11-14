import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from firmwaretrust.core import (
    FirmwareTrustError,
    VerificationError,
    generate_key_pair,
    sign_firmware,
    verify_firmware,
)


def write_pair(private_path, public_path):
    key = Ed25519PrivateKey.generate()
    private_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))


def test_keygen_sign_verify_round_trip(tmp_path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    firmware, manifest = tmp_path / "image.bin", tmp_path / "image.json"
    firmware.write_bytes(b"firmware-test-payload")
    assert len(generate_key_pair(private, public)) == 16
    sign_firmware(firmware, private, manifest)
    result = verify_firmware(firmware, manifest, public)
    assert result["verified"] is True
    assert result["size_bytes"] == len(b"firmware-test-payload")


def test_modified_firmware_is_rejected(tmp_path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    firmware, manifest = tmp_path / "image.bin", tmp_path / "image.json"
    write_pair(private, public)
    firmware.write_bytes(b"original")
    sign_firmware(firmware, private, manifest)
    firmware.write_bytes(b"tampered")
    with pytest.raises(VerificationError, match="digest mismatch"):
        verify_firmware(firmware, manifest, public)


def test_manifest_tampering_is_rejected(tmp_path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    firmware, manifest = tmp_path / "image.bin", tmp_path / "image.json"
    write_pair(private, public)
    firmware.write_bytes(b"same")
    sign_firmware(firmware, private, manifest)
    data = json.loads(manifest.read_text())
    data["created_at"] = "2099-01-01T00:00:00+00:00"
    manifest.write_text(json.dumps(data))
    with pytest.raises(VerificationError, match="signature is invalid"):
        verify_firmware(firmware, manifest, public)


def test_wrong_trust_anchor_is_rejected(tmp_path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    other_private, other_public = tmp_path / "other-private.pem", tmp_path / "other-public.pem"
    firmware, manifest = tmp_path / "image.bin", tmp_path / "image.json"
    write_pair(private, public)
    write_pair(other_private, other_public)
    firmware.write_bytes(b"payload")
    sign_firmware(firmware, private, manifest)
    with pytest.raises(VerificationError, match="key ID"):
        verify_firmware(firmware, manifest, other_public)


def test_keygen_refuses_to_overwrite_existing_key(tmp_path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    private.write_text("preserve")
    with pytest.raises(FirmwareTrustError, match="overwrite"):
        generate_key_pair(private, public)
    assert private.read_text() == "preserve"
