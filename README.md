# FirmwareTrust

**Firmware integrity, signing and release verification.**

FirmwareTrust is a software-first engineering project for producing verifiable firmware release artifacts and auditable metadata.

> **Development status: M0 prototype.** This milestone is a host-side signing and verification tool. It is not a hardware secure-boot implementation, device key-provisioning system, OTA updater, device-side anti-rollback mechanism, or production key-management service.

## M0 capabilities

- Generate Ed25519 signing key pairs.
- Calculate SHA-256 digests and artifact sizes.
- Create canonical, signed JSON release manifests.
- Verify firmware against a manifest and an independently supplied trusted public key.
- Reject modified firmware, altered manifest fields and mismatched trust anchors.
- Provide a CLI, automated tests and CI across Python 3.11–3.13.

## Quick start

Requires Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Generate a development key pair:

```bash
firmwaretrust keygen --private-key ./keys/dev-private.pem --public-key ./keys/dev-public.pem
```

Sign a firmware image:

```bash
firmwaretrust sign --firmware ./build/firmware.bin --private-key ./keys/dev-private.pem --manifest ./dist/firmware.manifest.json
```

Verify it using a separately trusted public key:

```bash
firmwaretrust verify --firmware ./build/firmware.bin --manifest ./dist/firmware.manifest.json --public-key ./keys/dev-public.pem
```

Protect private keys. Never commit them, upload them to CI, or use development keys for production signing.

A successful verification means the firmware digest, signed manifest and independently supplied public key agree. It does **not** prove that firmware is safe or that the public key is trustworthy.

## Architecture

The signer hashes the firmware, builds deterministic JSON metadata and signs the canonical payload with Ed25519. The verifier receives its trust anchor separately, checks the key identifier, recalculates the firmware digest and verifies the signature.

See:
- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Verification plan](docs/VERIFICATION.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## Roadmap

| Milestone | Scope | Status |
|---|---|---|
| M0 | Ed25519 signing, SHA-256 manifests, CLI, tests and CI | Initial foundation |
| M1 | Key rotation, revocation policy and signed release index | Planned |
| M2 | SBOM ingestion and firmware dependency analysis | Planned |
| M3 | Release registry, audit events and REST API | Planned |
| M4 | Update campaign simulator, staged rollout and recovery modelling | Planned |
| M5 | Bootloader integration and target-specific verification | Planned; requires hardware |

## Security boundaries

- The verifier does not trust a public key merely because it is named in a manifest.
- The trusted public key must be provisioned independently through an authenticated channel.
- Key custody, rotation, revocation and incident response are not production-grade.
- Ed25519 signatures do not provide secure boot, anti-rollback, confidentiality or runtime memory protection.
- This tool does not inspect whether signed firmware is benign.
- Do not use this prototype as the sole security control for safety-critical or other high-consequence systems.

## Development

```bash
python -m pip install -e ".[dev]"
pytest -q
ruff check .
```

## License

Apache-2.0. See [LICENSE](LICENSE).
