# Verification Plan

## Automated M0 checks

- Key generation creates Ed25519 PEM keys and a public-key identifier.
- A signed firmware image verifies with the matching public key.
- Modified firmware bytes are rejected.
- Modified signed metadata is rejected.
- A different trusted public key is rejected.
- Key generation refuses to overwrite existing key files.
- CLI help and argument parsing are exercised.

Run:

```bash
python -m pip install -e ".[dev]"
pytest -q
ruff check .
```

## Evidence classes

| Class | Meaning |
|---|---|
| Unit test | Function-level automated test |
| Integration test | CLI and package workflow test |
| Emulation | Execution in an emulator or simulated device |
| Hardware | Observation on a named physical target with recorded setup and results |
| Independent review | Findings from a qualified reviewer with documented scope |

Do not describe unit tests as hardware validation. M0 provides software-level tests only.

## Future validation

- Malformed and adversarial manifest corpus.
- Property-based and fuzz testing.
- Key rotation and revocation tests.
- Reproducible-build and provenance verification.
- Bootloader reference integration.
- Physical target tests recording board revision, toolchain, debugger, firmware digest, procedure and raw observations.
