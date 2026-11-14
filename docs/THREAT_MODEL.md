# Threat Model — M0

## Assets

- Firmware artifact integrity.
- Authenticity of release metadata.
- Confidentiality and integrity of signing private keys.
- Correct association between a release and its trusted signing key.

## Threats and controls

| Threat | M0 mitigation | Residual limitation |
|---|---|---|
| Firmware changed after signing | SHA-256 digest check | Hash does not establish firmware safety |
| Manifest fields changed | Ed25519 signature over canonical payload | Key compromise defeats authenticity |
| Attacker substitutes a key | External trust anchor and key-ID check | Trust-anchor provisioning is out of scope |
| Malformed manifest or algorithm downgrade | Schema and algorithm checks; fail-closed errors | Schema evolution needs policy |
| Accidental key overwrite | Keygen refuses existing key paths | Backup and lifecycle remain manual |

## Out of scope

- Compromised build machines or source repositories.
- Malicious but correctly signed firmware.
- Private-key exfiltration, HSM integration and threshold signing.
- Secure boot ROM, hardware root of trust and debug-port lockdown.
- OTA network attacks and device-side anti-rollback storage.
- Physical attacks, fault injection and side-channel analysis.
- Safety certification and regulatory compliance.

## Assumptions

1. The public key passed to `verify` is authentic and independently provisioned.
2. The signing private key has not been compromised.
3. The Python runtime and cryptography dependency are trustworthy.
4. The operator selects the intended artifact and manifest.

## Production hardening required

Define key custody, rotation and revocation; signed trust metadata; secure build provenance; reproducible builds; authenticated update transport; device-side boot verification; anti-rollback state; recovery behaviour; audit retention; and incident response.
