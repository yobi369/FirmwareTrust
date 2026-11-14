# Enterprise Delivery Plan

This plan turns the FirmwareTrust feature set into testable delivery gates. Status is deliberately conservative: the dedicated backend and initial tenant schema are deployed; the authenticated organization/project/release console is in preview. Database-level authenticated security tests now pass, while browser-driven auth/session validation and production operations remain open.

## Workstreams

### 1. Identity and organizations
- [x] Provision a dedicated Supabase project for FirmwareTrust (EU West, quoted $0/month).
- [x] Deploy initial organization, membership, project, release, key, SBOM, policy, approval, token, webhook and audit schema.
- [x] Enable tenant RLS and add owner succession, audit append-only and approval separation controls.
- [x] Secure creator-only first-owner bootstrap through a narrow private SECURITY DEFINER helper; the public RPC remains SECURITY INVOKER.
- [x] Add and execute transactional authenticated RLS integration coverage for first-owner bootstrap and cross-tenant read denial.
- [ ] Complete browser-driven auth/session lifecycle, invitation flow, cross-tenant write tests and owner succession.

### 2. Registry and audit
- Register immutable release metadata and signed manifests.
- Add append-only audit events with per-organization hash chaining.
- Add release search, filters, export and verification history.
- Test idempotency, concurrent submissions and audit-chain integrity.

### 3. Key lifecycle
- [x] Register public keys and SHA-256 fingerprints; keep private keys customer-controlled.
- [x] Implement atomic rotation, predecessor/successor relationships and irreversible revocation with reasons.
- [x] Preserve historical public-key evidence and append audit events for rotation/revocation.
- [x] Enforce Ed25519 public-key SPKI format and verify the 16-character M0 fingerprint against the raw public key bytes in the database trigger; reject private-key PEMs and mismatches.
- [x] Add and execute authenticated integration tests for role denial, cross-tenant denial, duplicate fingerprints, private-key PEM rejection, fingerprint mismatch rejection, immutable fields, rotation, revocation, audit-chain continuity and transaction rollback.
- [ ] Add compromised-key response tests against the future online verifier.
- [x] Add an optional signed organization/project trust scope to release manifests.
- [x] Deploy a minimal public key-status Edge Function; it returns only the status for the exact organization/project/key tuple and uses a server-side Supabase secret key.
- [x] Make registry-scoped browser verification fail closed when the key is not active or the registry cannot be reached.
- [ ] Complete browser end-to-end tests for active, rotated, revoked, expired, missing and unavailable registry states.

### 4. SBOM and vulnerability intelligence
- Parse CycloneDX JSON and SPDX JSON.
- Normalize components and purls.
- Integrate a documented vulnerability source with feed version and freshness.
- Add triage, exception expiry and rescanning.
- Test malformed documents, duplicate components, unmatched packages and stale feeds.

### 5. Governance and reporting
- Add versioned release policies and deterministic evaluation.
- Add approvals with separation of duties and quorum.
- Add executive and engineering reports with CSV/JSON export.
- Test policy changes after approval, expired exceptions and reviewer independence.

### 6. CI/CD
- Implement scoped, hashed API tokens and revocation.
- Implement signed webhooks and replay protection.
- Provide GitHub Actions and generic shell examples.
- Test token scope, token leakage prevention, webhook retries and idempotency.

## Release gates

| Gate | Exit criteria |
|---|---|
| A — Infrastructure | Dedicated backend project; secrets configured; schema deployed; RLS and auth integration tests pass |
| B — Core control plane | Organization/team workflows, release registry, audit history and key lifecycle work end-to-end |
| C — Intelligence | SBOM ingestion, component inventory, vulnerability findings and freshness surfaced |
| D — Governance | Policies, approvals, release gates, reports and CI/CD API available |
| E — Pilot-ready | Independent security review, operational runbooks, backup restore, monitoring, privacy/export process and pilot acceptance |

## Definition of done for a capability

A capability is not complete because a screen or endpoint exists. It must have:
- validated input and documented API behavior;
- server-side authorization and database tenant isolation;
- positive and negative automated tests;
- audit coverage for security-sensitive mutations;
- observable errors and operational metrics;
- user-facing documentation;
- deployment verification in the intended environment.

## Current blockers

FirmwareTrust now has a dedicated Supabase project (`dyqhzbsfopzejhqwdzgg`) separate from the user's unrelated databases. Its first tenant schema and security hardening migrations are deployed. The Vercel project has the public Supabase URL and publishable key configured; no service-role key is exposed to the browser.

The initial authenticated console is deployed as a preview and supports account sign-in/sign-up, organization creation, project creation, draft release metadata and signing-key lifecycle management. A transactional SQL integration suite at `supabase/tests/enterprise_rls_integration.sql` has been executed successfully against the dedicated Supabase project. It covers first-owner bootstrap, cross-tenant reads, developer-role key restrictions, duplicate active fingerprints, private-key PEM rejection, fingerprint mismatch rejection, immutable public-key material, key rotation/revocation and audit hash-chain continuity; fixtures are rolled back. The first-owner bootstrap was hardened in migration `202611140009_secure_private_organization_bootstrap.sql` after the live test exposed an RLS failure in the earlier invoker-only path. Migration `202611140010_enforce_ed25519_public_key_fingerprint.sql` now validates public-key encoding and fingerprint integrity at the database boundary. Registry-scoped manifests can now bind organization/project identifiers into the Ed25519-signed payload, and the deployed `key-status` Edge Function provides a minimal status lookup. The browser verifier checks that status and fails closed for non-active or unavailable registry results. The Edge Function is deployed, but the full browser-to-function path has not yet been exercised with real registered/revoked keys. Browser-driven auth/session testing, invitation expiry/replay, cross-tenant write coverage and production operational validation remain open. Team invitations, SBOM analysis, policy/approval execution, API token issuance, signed webhooks and enterprise reports are not yet implemented as complete hosted workflows. Foreign-key indexes and overlapping permissive RLS policies have been addressed; remaining performance notices are unused-index observations on this newly provisioned database and should be reassessed after representative workload data exists.
