# Online signing-key verification

## Purpose

A release manifest may carry an optional, signed `trust_registry` object:

```json
{
  "provider": "firmwaretrust",
  "organization_id": "<organization UUID>",
  "project_id": "<project UUID>"
}
```

The object is part of the canonical Ed25519-signed manifest payload. The browser therefore cannot change the registry scope without invalidating the signature.

## Verification sequence

1. Verify the Ed25519 signature against the independently supplied public key.
2. Recompute SHA-256 and artifact size and compare them with the signed manifest.
3. If the signed manifest has no `trust_registry` object, report cryptographic/offline verification only. Do not infer current signer authorization.
4. If the signed manifest has a registry scope, call `POST /functions/v1/key-status` with the organization UUID, project UUID and 16-character M0-compatible key ID.
5. Accept signer trust only when the registry returns `trusted: true` and `status: active`. Network or registry errors fail closed for registry-scoped manifests.

## Public endpoint contract

Request body:

```json
{
  "organization_id": "uuid",
  "project_id": "uuid",
  "key_id": "0123456789abcdef"
}
```

The endpoint returns only a minimal status result. It does not return organization names, member data, public-key PEM, revocation reasons, audit events or other tenant records. It reads through a server-side Supabase secret key held by the Edge Function runtime; no secret key is included in browser code.

Possible statuses include `active`, `rotated`, `revoked`, `expired`, `not_yet_valid`, `not_registered`, `unsupported_algorithm` and `ambiguous`.

## Trust boundaries and limitations

- The organization and project identifiers are bound into the manifest signature.
- The key ID is the existing M0-compatible first 16 hexadecimal characters of SHA-256 over the raw Ed25519 public key. The database trigger validates the PEM's Ed25519 SubjectPublicKeyInfo encoding and recomputes this fingerprint before accepting a registration, preventing a caller from attaching an arbitrary fingerprint or private-key PEM.
- The online endpoint checks the exact organization/project/key tuple. It does not independently certify firmware safety or prove a device enforces the result.
- Manifests without registry context remain compatible with offline verification, but cannot establish current registry status.
- Production hardening still requires rate limiting/abuse controls, browser end-to-end testing, independent security review and operational monitoring.

## Non-forgeable release verification attestation

The authenticated `register-release` Edge Function verifies the Ed25519 signature and active registry-key status before calling the service-only `register_verified_release` RPC. That RPC creates the draft release and its `release_verification_attestations` row in one database transaction. The RPC is executable only by the Supabase service role; authenticated and anonymous users cannot insert or mutate attestation rows.

Each attestation records the organization/project/release tuple, key fingerprint, Ed25519 algorithm, SHA-256 digest of the canonical signed payload, SHA-256 digest of the signature bytes, verifier version and server-side verification time. A database trigger checks the attestation scope, release artifact metadata and that the registered key was active at verification time. The attestation is immutable and appended to the organization audit chain.

Release policy evaluation now treats `require_signed_manifest` as requiring this attestation, not merely a signature-shaped JSON object. Release identity, artifact digest and manifest are immutable after registration. Publication requires an approved release, a matching server-created attestation and a fresh passing policy evaluation; the database repeats those checks during the status transition.
