# FirmwareTrust API Contract

**Status:** Proposed contract for implementation. Endpoints below are not yet deployed.

Base path: `/api/v1`. All tenant operations require an authenticated user session or scoped API token. The server derives the organization from authorized membership or token scope; clients must not be allowed to choose an arbitrary organization ID as an authorization shortcut.

## Authentication

- Interactive users authenticate through the configured identity provider.
- CI/CD uses organization/project-scoped API tokens.
- Tokens are generated with a one-time display, stored as a cryptographic hash, and support expiry and revocation.
- Send tokens using `Authorization: Bearer <token>`; never put tokens in query strings.
- Required token scopes are listed per endpoint below.

## Common response and errors

JSON responses use `application/json`. Errors use:

```json
{
  "error": {
    "code": "POLICY_BLOCKED",
    "message": "The release did not satisfy the active policy.",
    "request_id": "req_..."
  }
}
```

Use standard HTTP status codes: 400 malformed input, 401 unauthenticated, 403 unauthorized, 404 absent or inaccessible resource, 409 state conflict/idempotency conflict, 413 oversized payload, 422 validation or policy failure, 429 rate limited, 500 unexpected failure.

## Organizations and membership

| Method | Endpoint | Purpose | Access |
|---|---|---|---|
| POST | `/organizations` | Create organization and owner membership | Authenticated user |
| GET | `/organizations` | List caller's organizations | Member |
| GET | `/organizations/{orgId}/members` | List members | Owner/admin |
| POST | `/organizations/{orgId}/invitations` | Invite by email and role | Owner/admin |
| POST | `/invitations/{token}/accept` | Accept single-use invitation | Intended invitee |
| PATCH | `/organizations/{orgId}/members/{memberId}` | Change role or suspend membership | Owner/admin |
| DELETE | `/organizations/{orgId}/members/{memberId}` | Remove member | Owner/admin |

## Projects and releases

| Method | Endpoint | Purpose | Scope |
|---|---|---|---|
| POST | `/projects` | Create project | `projects:write` |
| GET | `/projects` | List accessible projects | `projects:read` |
| POST | `/projects/{projectId}/releases` | Register release metadata and signed manifest | `releases:write` |
| GET | `/projects/{projectId}/releases` | List releases with filters | `releases:read` |
| GET | `/releases/{releaseId}` | Retrieve release evidence | `releases:read` |
| POST | `/releases/{releaseId}/verify` | Verify supplied artifact against manifest and trust policy | `releases:verify` |
| POST | `/releases/{releaseId}/evaluate` | Evaluate active release policy | `policies:evaluate` |
| POST | `/releases/{releaseId}/publish` | Publish an approved immutable release | `releases:publish` |

Release creation requires an idempotency key and includes artifact digest, size, manifest, source revision and optional SBOM reference. The deployed Supabase Edge Function `POST /functions/v1/register-release` requires a valid user JWT, checks organization/project membership through RLS, verifies the Ed25519 manifest against an active registered public key, binds the signed registry scope to the selected organization/project, and inserts a draft release. A database trigger appends the release registration audit event in the same transaction. The service must not trust client-supplied `verified: true` flags. The current UI also permits explicitly marked unsigned metadata-only drafts; these are not cryptographically verified.

## Key lifecycle

| Method | Endpoint | Purpose | Scope |
|---|---|---|---|
| POST | `/projects/{projectId}/keys` | Register public key and fingerprint | `keys:write` |
| GET | `/projects/{projectId}/keys` | List public trust records | `keys:read` |
| POST | `/keys/{keyId}/rotate` | Record successor key and transition evidence | `keys:rotate` |
| POST | `/keys/{keyId}/revoke` | Revoke key with reason and effective time | `keys:revoke` |
| GET | `/keys/{keyId}/history` | Read lifecycle history | `keys:read` |

Only public key material is accepted. Private-key uploads are rejected.

## SBOM and vulnerabilities

| Method | Endpoint | Purpose | Scope |
|---|---|---|---|
| POST | `/releases/{releaseId}/sboms` | Ingest CycloneDX/SPDX document or digest-backed reference | `sbom:write` |
| GET | `/releases/{releaseId}/sbom` | Retrieve SBOM metadata and component summary | `sbom:read` |
| POST | `/releases/{releaseId}/vulnerability-scan` | Queue vulnerability analysis | `sbom:analyze` |
| GET | `/releases/{releaseId}/findings` | List findings and freshness | `findings:read` |
| PATCH | `/findings/{findingId}` | Record triage/exception status | `findings:triage` |

Ingestion is asynchronous for large documents. Responses expose `queued`, `processing`, `complete` or `failed` status and a stable job ID. Finding records include feed source and feed revision/time.

## Policies and approvals

| Method | Endpoint | Purpose | Scope |
|---|---|---|---|
| POST | `/projects/{projectId}/policies` | Create a draft policy version | `policies:write` |
| POST | `/policies/{policyId}/activate` | Activate immutable version | `policies:activate` |
| GET | `/projects/{projectId}/policies` | List versions | `policies:read` |
| POST | `/releases/{releaseId}/approvals` | Approve or reject bound release digest | `approvals:decide` |
| GET | `/releases/{releaseId}/approvals` | List approval decisions | `approvals:read` |
| GET | `/organizations/{orgId}/reports/releases` | Release assurance report | `reports:read` |
| GET | `/organizations/{orgId}/reports/security` | Key, SBOM and vulnerability report | `reports:read` |
| GET | `/organizations/{orgId}/audit-events` | Filtered audit history | `audit:read` |

Approval decisions bind to release digest, manifest digest and policy version. A changed release or policy requires new evaluation and approvals. The author cannot approve their own release when separation of duties is enabled.

## CI/CD integrations

| Method | Endpoint | Purpose | Scope |
|---|---|---|---|
| POST | `/api-tokens` | Create scoped CI token | `tokens:write` |
| GET | `/api-tokens` | List token metadata (never token values) | `tokens:read` |
| DELETE | `/api-tokens/{tokenId}` | Revoke token | `tokens:revoke` |
| POST | `/webhooks` | Register signed event destination | `integrations:write` |
| POST | `/webhooks/{webhookId}/test` | Send test event | `integrations:write` |
| GET | `/integrations/events` | Read delivery attempts | `integrations:read` |

Webhook events include `release.created`, `release.verified`, `release.policy_blocked`, `release.approved`, `release.published`, `key.rotated`, `key.revoked`, `sbom.analysis_completed` and `finding.critical`.

Webhook requests include a timestamp and HMAC signature over the raw request body. Consumers must verify the signature, enforce timestamp tolerance and deduplicate the event ID. FirmwareTrust retries transient failures with bounded exponential backoff.

## Initial CI job sequence

1. Build firmware.
2. Generate or retrieve the signing identity in the customer's secure signing environment.
3. Sign the artifact and create the manifest locally.
4. Register the public key if it is not already trusted.
5. Submit release metadata and SBOM.
6. Wait for policy evaluation.
7. Fail the pipeline when the policy is blocked or approvals are required but absent.
8. Publish only after approval.
9. Preserve release ID, manifest digest and verification report as pipeline artifacts.

## Compatibility and versioning

The API is versioned by path. Additive optional fields are backward-compatible. Breaking changes require a new major path and a published migration window. All write endpoints should accept an `Idempotency-Key` header and return a request correlation ID.
