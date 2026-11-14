# CI/CD API Tokens

## Current supported capability

FirmwareTrust currently supports organization-issued API tokens for authenticated signed-release registration. The only active token scope is:

- `releases:write` — register a signed firmware release through the `register-release` Edge Function.

Other planned scopes (release read, SBOM write, key read and audit read) are not enabled until their corresponding API endpoints and tests exist.

## Issuance and storage

Organization owners and admins can issue a token from the Enterprise Console. Each token:

- Is generated with 256 bits of cryptographically secure random material.
- Uses the `ft_live_` prefix.
- Is displayed once at creation; FirmwareTrust cannot retrieve it later.
- Is stored only as a SHA-256 digest, with a short display prefix.
- Has one or more explicit project IDs, unless the administrator deliberately selects organization-wide access.
- Must expire within 365 days.
- Is immutable after creation and can only be revoked, not edited or deleted.

The database denies direct authenticated inserts and updates, withholds the stored token hash from authenticated SELECT privileges, and exposes controlled create/revoke RPCs. Creation and revocation append audit events. Token revocation is irreversible.

## Release registration

Use the same signed-release registration endpoint as a user session:

```http
POST /functions/v1/register-release
Authorization: Bearer ft_live_<secret>
Content-Type: application/json
```

The JSON body is the same as the authenticated release-registration contract: organization ID, project ID, version, artifact filename, SHA-256 digest and signed FirmwareTrust manifest.

The Edge Function hashes the presented token, looks up the matching credential using its server-only Supabase secret, and checks organization, project, `releases:write` scope, expiry, revocation and the token creator's current membership/role. It then verifies the active Ed25519 signing key and manifest signature.

The database rechecks the token digest, organization, project scope, scope grant, expiry, revocation and actor identity inside the same transaction that creates the release and its immutable verification attestation. A row lock serializes registration with revocation so a token revoked first cannot be used to register a release.

## Operational handling

- Store tokens in GitHub Actions Secrets or another CI/CD secret manager.
- Never commit tokens, print them in workflow logs or embed them in client-side code.
- Use one token per pipeline or deployment environment where practical.
- Select project-level restrictions unless cross-project access is required.
- Revoke and replace a token if it is lost or exposed.
- Token usage time is updated after a successful release registration.

## Current limitations

- The token endpoint currently supports only signed release registration; metadata-only release creation is not exposed through API tokens.
- SBOM ingestion, read-only release queries, key-status reads and audit exports do not yet accept API tokens.
- Rate limiting, token usage analytics, rotation automation and live CI-provider end-to-end tests remain production hardening tasks.
