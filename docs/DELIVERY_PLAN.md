# Enterprise Delivery Plan

This plan tracks implementation and validation of FirmwareTrust's commercial control plane. Status distinguishes deployed backend capabilities from browser/runtime validation and production operations.

## Workstreams

### 1. Identity and organizations
- [x] Provision a dedicated Supabase project for FirmwareTrust in EU West.
- [x] Deploy organization, membership, project, release, key, SBOM, policy, approval, token, webhook, invitation and audit schemas.
- [x] Enable tenant RLS with action-specific policies and secure first-owner bootstrap.
- [x] Add authenticated SQL integration coverage for first-owner bootstrap, tenant isolation and role restrictions.
- [x] Add owner/admin-managed team invitations with one-time 256-bit tokens, SHA-256 hashes at rest, email binding, 1–30 day expiry, revocation, acceptance and audit events.
- [x] Add Enterprise Console invitation creation, pending/accepted/revoked/expired listing and one-time copyable links.
- [ ] Add email delivery provider integration and browser E2E for signup, email mismatch, expiry and acceptance.
- [ ] Complete browser auth/session lifecycle, cross-tenant write tests and owner succession.

### 2. Release registry and audit
- [x] Register signed Ed25519 manifests through authenticated Edge Functions after active registry-key and tenant checks.
- [x] Persist immutable server-side verification attestations atomically with trusted release registration.
- [x] Freeze release identity, artifact digest and manifest after registration/review begins.
- [x] Append transactional audit events for release registration, attestations, review decisions, publication, key lifecycle and SBOM ingestion.
- [x] Preserve hash-chain continuity and test it in the authenticated SQL integration suite.
- [x] Add scoped API read access to release metadata and audit history.
- [ ] Add idempotency keys, richer search/filter/export and long-term verification history UI.
- [ ] Add live Edge Function tests for valid, tampered, revoked-key, cross-tenant and duplicate-version submissions.

### 3. Key lifecycle
- [x] Register Ed25519 public keys only; private signing keys remain customer-controlled.
- [x] Validate SPKI encoding and M0-compatible key fingerprint in the database.
- [x] Enforce immutable public-key material, duplicate active fingerprint rejection, atomic rotation and irreversible revocation with reason.
- [x] Preserve key lifecycle audit events and historical key evidence.
- [x] Deploy a minimal public key-status Edge Function; it returns only status for the exact organization/project/key tuple.
- [x] Make browser verification fail closed when a scoped key is not active or registry status cannot be reached.
- [x] Add scoped API key-registry reads without exposing public-key PEM or private material.
- [ ] Complete browser E2E for active, rotated, revoked, expired, missing and unavailable key states.

### 4. SBOM and vulnerability intelligence
- [x] Parse CycloneDX JSON and SPDX JSON, including nested components and package URLs.
- [x] Normalize/deduplicate components and retain original document SHA-256 evidence.
- [x] Persist SBOM documents, normalized components and audit events atomically.
- [x] Integrate OSV.dev querybatch, advisory hydration and component-scoped vulnerability findings.
- [x] Persist scan status, source/time, checked-component count, finding count and partial-scan warnings.
- [x] Follow bounded OSV querybatch continuation and mark capped scans partial.
- [x] Add Enterprise Console SBOM inventory and vulnerability findings.
- [x] Add scoped API-token SBOM ingestion. The service validates the token again inside the same database transaction as SBOM persistence and audit insertion.
- [x] Add Deno tests for CycloneDX/SPDX normalization, PURL parsing, deduplication, severity mapping, affected ranges and Ed25519 manifest verification.
- [ ] Add scheduled rescans, freshness alerts, triage, false-positive exceptions and exception expiry.
- [ ] Add live integration tests for malformed documents, unmatched PURLs, OSV partial/unavailable states and cross-tenant denial.

### 5. Governance and reporting
- [x] Add tenant-scoped deterministic release-policy evaluation for attestation, SBOM presence/completeness, vulnerability thresholds and independent approvals.
- [x] Validate policy rule shapes, supported keys and types; project policy precedence over organization policy.
- [x] Add policy version authoring/listing/evaluation in the Enterprise Console.
- [x] Pin policy versions when a release enters review.
- [x] Add independent approval/rejection decisions, separation of duties and immutable reviewer decisions.
- [x] Enforce quorum and policy evidence before approval; direct status updates use the same database guard.
- [x] Add an atomic publish RPC and database transition guard that rechecks authorization, attestation and policy evidence.
- [x] Test successful and blocked publication paths in the authenticated SQL integration suite.
- [ ] Add executive/engineering reports with CSV/JSON export.
- [ ] Test policy changes after approval, expired exceptions and reviewer independence.

### 6. CI/CD and API integrations
- [x] Issue high-entropy `ft_live_` API tokens once; store SHA-256 hashes only.
- [x] Enforce owner/admin issuance, expiry, immutable scopes/project restrictions and irreversible revocation.
- [x] Add safe token metadata listing without exposing token hashes.
- [x] Validate token organization, scope, project restriction, expiry and revocation on every gateway request; update last-used time.
- [x] Add API gateway routes for release listing, Ed25519-signed release registration, signing-key metadata reads, audit history reads and SBOM ingestion.
- [x] Revalidate API-token scope/revocation/project at the same database transaction as release+attestation registration and SBOM persistence.
- [x] Provide versioned API contract and CI/CD request examples.
- [ ] Add GitHub Actions/provider end-to-end tests, usage telemetry and rate limits.
- [ ] Add signed webhooks, replay protection and webhook delivery tests.

## Current backend and validation state

- Dedicated Supabase project: `dyqhzbsfopzejhqwdzgg`.
- Applied database migrations: **001–042**.
- Edge Functions: `key-status` v2, `register-release` v7, `ingest-sbom` v11 and `api-gateway` v6.
- Supabase security advisor: zero findings after the latest schema changes.
- Performance advisor: no remaining missing-FK-index or overlapping permissive RLS warnings. Remaining unused-index notices are informational and should be reassessed after representative workload data exists.
- The authenticated SQL integration suite passed against the dedicated project after release governance, verification attestations, invitations and API-token changes. It covers tenant isolation, role restrictions, invitation token hashing/email binding/acceptance/revocation/audit, attestation forgery denial, policy-gated approval/publication, API-token scope/project/expiry/revocation and API-token SBOM ingestion. Fixtures roll back.
- Latest Deno test/type-check run passed the SBOM, Ed25519 and API-token suites and type-checked the Edge Functions, including the API gateway and SBOM API-token path.
- GitHub Actions CI run #370 passed across Python 3.11/3.12/3.13, browser syntax/lint, Deno SBOM/Ed25519/API-token tests and Edge Function type checks.

## Release gates

| Gate | Exit criteria | Current assessment |
|---|---|---|
| A — Infrastructure | Dedicated backend, secrets, schema, RLS and auth integration tests | Backend foundation and SQL security suite pass |
| B — Core control plane | Team, release registry, audit and key lifecycle end-to-end | Database and console workflows implemented; browser E2E remains |
| C — Intelligence | SBOM ingestion, inventory, vulnerability findings and freshness | Ingestion and OSV enrichment implemented; scheduled rescans remain |
| D — Governance | Policies, approvals, release gates, reports and CI/CD API | Policies, approvals, publication and initial CI/CD API implemented; reports/webhooks remain |
| E — Pilot-ready | Independent review, runbooks, restore, monitoring, privacy/export and pilot acceptance | Not yet met |

## Current blockers

The dedicated Supabase backend is separate from the user's other projects. Publishable credentials are used by browser code; server-only secret credentials are confined to Edge Function runtimes. No service-role/secret key is shipped to the browser or committed to the repository.

The current enterprise implementation is committed on `feature/enterprise-platform-foundation` and remains in draft PR #1. Vercel is currently rejecting new preview builds because of its build-rate limit. Therefore the latest Enterprise Console changes are not yet confirmed live in a new preview; the permanent production URL still serves the older M0 workbench.

The backend supports authenticated signed-release registration, key lifecycle, SBOM/OSV ingestion, versioned policies, independent approvals, policy-gated publication, one-time team invitations and scoped CI/CD API tokens. The API gateway currently serves release read/write, key registry read, audit read and SBOM ingestion. The full browser-to-function workflows still need end-to-end testing with real sessions and API tokens.

Remaining production gates include email delivery for invitations, scheduled OSV rescans/triage, signed webhooks, executive reporting, API rate limiting/usage telemetry, independent security review, backup/restore verification, monitoring, incident runbooks and pilot acceptance. No production-readiness claim is made until these gates are completed.
