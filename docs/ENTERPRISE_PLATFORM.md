# FirmwareTrust Enterprise Platform Architecture

**Status:** Architecture baseline for the M1–M3 implementation. This document is not evidence that hosted services are deployed or production-ready.

## Product boundary

FirmwareTrust extends the existing local signing and verification workbench into a hosted release-assurance control plane. The browser/CLI remains the cryptographic client. The hosted service stores release metadata, public trust material, SBOMs, policy decisions and audit evidence; it must not receive customer firmware-signing private keys.

## Capability map

| Capability | Platform responsibility | Security invariant |
|---|---|---|
| Organization and team accounts | Organizations, projects, memberships, invitations and role-scoped access | Every tenant-owned record is organization-scoped and protected by server authorization plus database RLS |
| Release registry and audit | Immutable release metadata, artifact digests, manifests, verification results and append-only audit events | Store evidence and hashes by default; artifact binaries are optional, private and retention-controlled |
| Key lifecycle | Public-key registration, activation, rotation, revocation, expiry and trust history | Private keys remain customer-controlled; revocation is prospective and never rewrites historic verification evidence |
| SBOM and vulnerability intelligence | CycloneDX/SPDX ingestion, component inventory, vulnerability matching and refreshable findings | Preserve source, version, timestamp and confidence; distinguish unknown from not affected |
| Release policies and approvals | Versioned policy rules, evaluation results, approval quorum, separation of duties and release state transitions | A release cannot be promoted while required checks or approvals are outstanding |
| CI/CD integrations | Scoped API tokens, webhook endpoints, signed callbacks and pipeline status APIs | Tokens are stored as hashes, shown once, scoped and revocable |

## Proposed service architecture

1. **Identity:** Supabase Auth for authentication; organization membership is application data, never inferred from user-editable profile metadata.
2. **Authorization:** PostgreSQL RLS for tenant isolation, with server-side authorization for privileged transitions. The service role key is server-only.
3. **Control plane:** Vercel serverless API routes for organization, release, key, policy, approval and integration operations.
4. **Evidence store:** Postgres for structured metadata and audit events; private object storage for optional SBOM documents and uploaded artifacts. Signed release manifests and public keys are retained as evidence.
5. **Analysis workers:** Asynchronous SBOM parsing and vulnerability enrichment. Each finding records the vulnerability source and database revision used.
6. **Client integrations:** REST API, CLI adapter, GitHub Actions example and generic CI webhook contract.

## Tenant model

- An organization is the security boundary.
- A project belongs to exactly one organization.
- A user can belong to multiple organizations with different roles.
- Membership roles: `owner`, `admin`, `security_reviewer`, `release_manager`, `developer`, `viewer`.
- Role names are not sufficient on their own: every operation also checks organization membership, project scope, resource state and required approval separation.
- Invitations are time-limited, single-use and bound to the intended email address.
- Organization deletion and export require explicit owner confirmation and auditable lifecycle events.

## Release lifecycle

`draft → submitted → policy_evaluation → awaiting_approval → approved → published`

Terminal or exceptional states include `rejected`, `revoked` and `superseded`. A published release is immutable; corrections create a new release revision. Approval decisions bind to a release digest, manifest digest, policy version and reviewer identity. Changing any bound input invalidates previous approvals and requires re-evaluation.

A registry record should contain:
- organization and project IDs;
- semantic version/build identifier and source revision;
- artifact SHA-256 and byte size;
- signed manifest and signer key ID;
- SBOM digest, format and analysis status;
- policy version and evaluation summary;
- approval decisions and publication timestamps.

## Key lifecycle model

A key record stores the public key, algorithm, fingerprint, owner/project scope, status, validity window, predecessor/successor references and lifecycle events. Private key material is never stored in the registry. Rotation creates a successor key and records a signed transition statement where the customer can provide one. Revocation requires a reason, actor, effective timestamp and optional compromise timestamp.

Verification responses must report:
- signature validity;
- artifact digest and size match;
- key fingerprint match;
- key status at signing time and at verification time;
- trust-policy outcome;
- historical evidence limitations.

Do not collapse a historically valid signature into a failed signature merely because the key is revoked today. Report the historical signature result and current trust status separately.

## SBOM and vulnerability model

Accept CycloneDX JSON and SPDX JSON initially; reject unsupported formats with actionable errors. Store the original document privately, its digest, format, tool/source metadata and ingestion timestamp. Normalize packages to package URL (purl), version, supplier and license fields where present.

Vulnerability findings must include identifier (for example CVE or GHSA), affected component identity, affected-version evidence, severity source, status, first/last observed timestamps, upstream reference and remediation state. Never imply a clean bill of health when a component cannot be matched or vulnerability feeds are stale. A scan result is a time-bound assessment, not a permanent guarantee.

## Policy and approval model

Policies are versioned and immutable after publication. A policy evaluation is reproducible and records the exact policy version and evidence inputs. Initial policy controls:
- required valid signature and trusted active key;
- approved algorithm and minimum digest requirements;
- required SBOM presence and supported format;
- vulnerability severity thresholds and exception expiry;
- required number and roles of approvers;
- separation of duties (author cannot approve own release);
- mandatory release metadata and provenance fields.

Exceptions require reason, owner, expiry and audit event. A policy update applies to future evaluations; it must not silently rewrite historical decisions.

## Audit requirements

Audit events are append-only, tenant-scoped and emitted for membership changes, invitations, key lifecycle changes, release submissions, verification, SBOM ingestion, policy changes, approvals, publication, token management and integration configuration. Events include actor, organization, action, resource type/ID, timestamp, request correlation ID and redacted structured metadata. Do not put secrets, passphrases, private keys or raw API tokens in audit payloads.

For tamper evidence, chain event hashes per organization using a canonical event representation. This provides detection evidence, not absolute immutability against a database administrator; external anchoring or WORM retention is a later enterprise control.

## Operational and privacy controls

- TLS in transit and managed encryption at rest.
- RLS enabled on every exposed tenant table; no broad authenticated-only policy without tenant predicates.
- Publishable Supabase key only in browser code; service-role/secret keys only in server environment.
- API tokens stored as one-way hashes; support expiry, last-used time and immediate revocation.
- Rate limits and request-size limits for SBOM and webhook endpoints.
- Idempotency keys for release creation, ingestion and webhook delivery.
- Signed webhook payloads, timestamp tolerance and replay protection.
- Private storage buckets with organization-scoped object paths and RLS.
- Export, retention and deletion controls with legal-hold support before enterprise launch.
- Security review, dependency scanning, backup/restore exercise and incident runbook before production claims.

## Delivery gates

### Gate A — Backend foundation
Dedicated database, auth configuration, tenant schema, RLS policies, migrations, integration tests and secret management.

### Gate B — Core enterprise workflow
Organization setup, invitations, role enforcement, release registry, immutable audit events and key lifecycle.

### Gate C — Supply-chain intelligence
SBOM parsing, component normalization, vulnerability feed adapters, freshness indicators and reproducible policy evaluation.

### Gate D — Governance and integrations
Approval workflows, release gates, API tokens, webhooks, CI examples, reporting and export.

### Gate E — Launch assurance
Independent security review, tenant-isolation tests, abuse/rate-limit tests, backup restore, operational monitoring, documentation and pilot acceptance.

## Explicit non-goals for the first hosted release

No hosted custody of customer signing private keys, no claim of secure boot, no device-side anti-rollback, no OTA fleet control, no automatic proof that firmware is benign, and no certification claim without an external assessment.
