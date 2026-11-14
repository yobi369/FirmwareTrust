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
- [x] Validate signed Ed25519 manifests against an active registered public key and persist draft release records through an authenticated Edge Function.
- [x] Append a per-organization audit event transactionally when a release is registered.
- Add immutable release metadata, idempotency, release search, filters, export and verification history.
- [x] Test release audit insertion and audit-chain continuity in the authenticated SQL integration suite.
- [ ] Add Edge Function integration tests for valid, tampered, revoked-key, cross-tenant and duplicate-version submissions.

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
- [x] Parse CycloneDX JSON and SPDX JSON, including nested CycloneDX components and SPDX package URLs.
- [x] Normalize and deduplicate components by purl/name/version and retain document SHA-256 evidence.
- [x] Add atomic tenant-scoped SBOM ingestion and audit event creation through the authenticated database RPC.
- [x] Integrate OSV.dev querybatch and hydrate advisory details; persist findings per affected component with source modification timestamps.
- [x] Persist scan status, scan source/time, checked-component count, finding count and partial-scan warnings on each SBOM record.
- [x] Surface SBOM inventory and recent vulnerability findings in the Enterprise Console.
- [x] Follow OSV querybatch page tokens for up to five bounded continuation rounds; persist partial status if additional pages remain.
- [ ] Add scheduled rescans, freshness alerts, triage, false-positive exceptions and exception expiry.
- [x] Add Deno unit tests for CycloneDX/SPDX normalization, root/nested components, PURL version detection, deduplication, severity mapping and affected ranges; CI type-checks all three Edge Functions.
- [ ] Add live Edge Function integration tests for malformed documents, unmatched PURLs, OSV partial/unavailable states and cross-tenant denial.

### 5. Governance and reporting
- [x] Add a tenant-scoped deterministic release policy evaluator for signed-manifest declarations, SBOM presence/completeness, vulnerability thresholds and independent approval counts.
- [x] Validate policy rule object shape, supported keys and primitive types; project policies take precedence over organization policies.
- [x] Add a negative-path integration assertion proving incomplete evidence blocks a release.
- [x] Add immutable release verification attestations that only the service-role registration path can create; authenticated and anonymous clients cannot insert or mutate attestations.
- [x] Add console controls to create versioned organization/project policies, list applicable policy versions and evaluate a selected release.
- [x] Add policy-version pinning when a release enters review; policy versions and approval decisions are immutable.
- [x] Add independent approval/rejection decisions with reviewer identity checks, one decision per reviewer per release/policy, and append-only audit events.
- [x] Enforce policy evaluation and approval quorum before a release can become approved; direct status updates use the same database guard.
- [x] Freeze release identity, artifact digest and manifest after review begins; add reviewer-only status update scope without granting metadata mutation.
- [ ] Complete expanded authenticated integration execution after the review workflow changes.
- [x] Bind Ed25519 verification in the authenticated Edge Function to a service-role-only, atomic release-plus-attestation RPC.
- [x] Make the signed-manifest policy rule depend on the non-forgeable attestation rather than manifest field presence.
- [x] Add a policy-gated publication RPC and database transition guard that re-check authorization, attestation and policy evidence.
- [ ] Add executive and engineering reports with CSV/JSON export.
- [ ] Test policy changes after approval, expired exceptions and reviewer independence.

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

The initial authenticated console is deployed as a preview and supports account sign-in/sign-up, organization creation, project creation, metadata-only draft releases, signed-manifest release registration and signing-key lifecycle management. A transactional SQL integration suite at `supabase/tests/enterprise_rls_integration.sql` has been executed successfully against the dedicated Supabase project. It covers first-owner bootstrap, cross-tenant reads, developer-role key restrictions, duplicate active fingerprints, private-key PEM rejection, fingerprint mismatch rejection, immutable public-key material, key rotation/revocation and audit hash-chain continuity; fixtures are rolled back. The first-owner bootstrap was hardened in migration `202611140009_secure_private_organization_bootstrap.sql` after the live test exposed an RLS failure in the earlier invoker-only path. Migration `202611140010_enforce_ed25519_public_key_fingerprint.sql` now validates public-key encoding and fingerprint integrity at the database boundary. Registry-scoped manifests can now bind organization/project identifiers into the Ed25519-signed payload, and the deployed `key-status` Edge Function provides a minimal status lookup. The browser verifier checks that status and fails closed for non-active or unavailable registry results. The `key-status`, authenticated `register-release` and authenticated `ingest-sbom` Edge Functions are deployed. The SQL suite verifies release and SBOM audit insertion, component RLS, per-component finding uniqueness and rollback, but the full browser-to-function paths have not yet been exercised with real user sessions and external OSV responses. Browser-driven auth/session testing, invitation expiry/replay, cross-tenant write coverage and production operational validation remain open. Release review requests, independent approval/rejection decisions, pinned policy versions, non-forgeable verification attestations and policy-gated publication are implemented in the database and Enterprise Console. The latest Edge Function and UI changes still require runtime deployment verification. Team invitations, scoped API token issuance, signed webhooks and enterprise reports remain incomplete hosted workflows. Foreign-key indexes and overlapping permissive RLS policies have been addressed; remaining performance notices are unused-index observations on this newly provisioned database and should be reassessed after representative workload data exists. The release UPDATE RLS policies were consolidated after the review-role addition; the performance advisor no longer reports overlapping permissive policies.
