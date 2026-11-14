# CI/CD API Tokens

## Current supported capability

FirmwareTrust supports organization-issued API tokens through the deployed `api-gateway` Edge Function. The currently active scopes are:

- `releases:write` — register a signed firmware release.
- `releases:read` — read release metadata.
- `keys:read` — read public signing-key lifecycle metadata.
- `audit:read` — read organization audit events, optionally filtered to an allowed project.
- `sboms:write` — ingest CycloneDX/SPDX JSON SBOMs and trigger OSV.dev enrichment.

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

Use the API gateway signed-release route:

```http
POST /functions/v1/api-gateway/releases
Authorization: Bearer ft_live_<secret>
Content-Type: application/json
```

The JSON body contains project ID, version, artifact filename, SHA-256 digest and signed FirmwareTrust manifest. The organization is derived from the validated API token; the client cannot select another tenant.

The gateway verifies the presented token through the restricted `verify_api_token` RPC, then checks organization, project, scope, expiry, revocation and the token creator's current membership/role. It then verifies the active Ed25519 signing key and manifest signature.

The gateway hashes the presented token and the database rechecks that digest, organization, project scope, `releases:write` grant, expiry, revocation and actor identity inside the same transaction that creates the release and its immutable verification attestation. A row lock serializes registration with revocation so a token revoked first cannot be used to register a release.

## SBOM ingestion

Use the API gateway SBOM route:

```http
POST /functions/v1/api-gateway/sboms
Authorization: Bearer ft_live_<secret>
Content-Type: application/json

{
  "project_id": "<project-uuid>",
  "release_id": null,
  "document_text": "<CycloneDX or SPDX JSON document>"
}
```

The gateway enforces the `sboms:write` scope and project restriction, then forwards the credential to the SBOM ingestion Edge Function. That function re-verifies the token and the database performs a second token digest/scope/expiry/revocation check inside the same transaction as SBOM persistence and audit insertion. The token creator must remain an authorized organization member.

## Operational handling

- Store tokens in GitHub Actions Secrets or another CI/CD secret manager.
- Never commit tokens, print them in workflow logs or embed them in client-side code.
- Use one token per pipeline or deployment environment where practical.
- Select project-level restrictions unless cross-project access is required.
- Revoke and replace a token if it is lost or exposed.
- Token usage time is updated after a successful release registration.

## Current limitations

- API-token release registration requires a registry-scoped Ed25519-signed manifest; metadata-only release creation is not exposed through API tokens.
- Scheduled SBOM rescans, freshness alerts and vulnerability triage are not yet included in the API-token route.
- Rate limiting, token usage analytics, rotation automation and live CI-provider end-to-end tests remain production hardening tasks.
