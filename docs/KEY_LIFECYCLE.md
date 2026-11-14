# Signing-key lifecycle

FirmwareTrust registers public verification material only. Customer signing private keys remain under customer control and must never be sent to the enterprise API or stored in this database.

## Supported lifecycle

- **Register:** submit a PEM SubjectPublicKeyInfo public key. The browser computes a SHA-256 fingerprint over the decoded DER bytes. The database accepts only supported algorithms and creates the key in the active state.
- **Rotate:** the authenticated security role selects an active key and supplies its successor public key. A single database transaction marks the predecessor rotated, inserts the successor with a `rotated_from` link, and appends an audit event. A failed insert or audit operation rolls the transaction back.
- **Revoke:** the authenticated security role supplies a reason. The active key becomes revoked with a timestamp and an audit event. Revocation is irreversible through the client API.
- **Historical evidence:** public key material and fingerprints are immutable. Old keys remain available for historical signature verification; current trust status must be checked separately.

## Authorization and database invariants

- Only organization owners, admins and security analysts can manage keys.
- RLS scopes all reads and writes to organization membership and the key-management role.
- Security-definer membership and audit helpers live in a non-exposed `private` schema; public RPCs for organization creation and key lifecycle use SECURITY INVOKER.
- A partial unique index prevents duplicate active fingerprints within an organization/project scope.
- The lifecycle trigger prevents public material, fingerprint, algorithm, ownership and scope from being changed after registration.
- Only active keys may transition to rotated, revoked or expired.
- Key rows cannot be deleted.
- Rotation requires a predecessor in the same organization/project scope and a rotated predecessor state.
- Revocation requires a meaningful reason (3–1000 characters).

## Browser workflow

The Enterprise Console exposes the key registry after a project is selected. It accepts only a PEM block labelled `PUBLIC KEY`, calculates the fingerprint locally with Web Crypto, and never transmits a private key. Rotation requires a successor public key before the operator selects the predecessor to rotate. Revocation requires a reason and a confirmation step.

## API RPC

- `POST /rest/v1/rpc/rotate_signing_key`: `target_org`, `old_key_id`, `new_fingerprint`, `new_public_key_pem`, `new_algorithm`.
- `POST /rest/v1/rpc/revoke_signing_key`: `target_org`, `target_key_id`, `reason`.

Both RPC functions run as SECURITY INVOKER, require a signed-in user and verify the caller's organization role. They are not substitutes for independent review, end-to-end authorization tests or a production incident-response runbook.

## Remaining verification

Before marking this capability production-ready, add authenticated integration tests for successful registration/rotation/revocation, unauthorized-role denial, cross-tenant denial, duplicate fingerprint rejection, immutable-field rejection, delete rejection, transaction rollback, and audit-chain continuity. Also validate that the firmware verification path treats revoked keys as untrusted while preserving historical verification records.
