# Architecture

## M0 signing and verification flow

```text
Firmware image
    -> SHA-256 digest and byte length
    -> canonical release metadata
    -> Ed25519 signature
    -> signed JSON manifest

Firmware + manifest + independently trusted public key
    -> digest and size checks
    -> signature verification
    -> verification result
```

The verifier does not trust a public key simply because it appears in release metadata. It requires an independently supplied public key and checks the manifest key identifier against that key.

The signature covers every top-level manifest field except the signature value itself. The signed signature metadata contains the algorithm and key identifier. JSON is serialized with sorted keys, compact separators and UTF-8 encoding.

## Module boundaries

- `core.py`: hashing, key loading, manifest creation and verification.
- `cli.py`: command-line interface and exit codes.
- Planned `registry/`: release records and audit events.
- Planned `api/`: authenticated release-management API.
- Planned `policy/`: key rotation, revocation and rollout policy.
- Planned `agents/`: device update and status protocol adapters.

M0 intentionally excludes a bootloader and network update agent.
