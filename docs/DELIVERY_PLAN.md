# Enterprise Delivery Plan

This plan turns the FirmwareTrust feature set into testable delivery gates. Status is deliberately conservative: the dedicated backend and initial tenant schema are deployed; the first authenticated organization/project/release console is in preview and has not yet passed end-to-end security validation.

## Workstreams

### 1. Identity and organizations
- [x] Provision a dedicated Supabase project for FirmwareTrust (EU West, quoted $0/month).
- [x] Deploy initial organization, membership, project, release, key, SBOM, policy, approval, token, webhook and audit schema.
- [x] Enable tenant RLS and add owner succession, audit append-only and approval separation controls.
- [ ] Complete auth/session lifecycle, invitation flow and cross-tenant negative integration tests.
- Test cross-tenant reads/writes, invitation expiry/replay and owner succession.

### 2. Registry and audit
- Register immutable release metadata and signed manifests.
- Add append-only audit events with per-organization hash chaining.
- Add release search, filters, export and verification history.
- Test idempotency, concurrent submissions and audit-chain integrity.

### 3. Key lifecycle
- [x] Register public keys and SHA-256 fingerprints; keep private keys customer-controlled.
- [x] Implement atomic rotation, predecessor/successor relationships and irreversible revocation with reasons.
- [x] Preserve historical public-key evidence and append audit events for rotation/revocation.
- [ ] Add authenticated integration tests for compromised-key response, role denial, cross-tenant denial, duplicate fingerprints, immutable fields and transaction rollback.
- [ ] Connect key revocation status to every release verification path.

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

The initial authenticated console is deployed as a preview and supports account sign-in/sign-up, organization creation, project creation and draft release metadata. It still requires end-to-end browser testing, auth configuration review, cross-tenant denial tests and operational validation. Team invitations, SBOM analysis, policy/approval execution, API token issuance, signed webhooks and enterprise reports are not yet implemented as complete hosted workflows. The key lifecycle UI and database transitions are implemented, but authenticated integration tests and wiring revocation state into every signature-verification path remain open. The latest Supabase security advisor scan is clear. Foreign-key indexes and overlapping permissive RLS policies have been addressed; remaining performance notices are unused-index observations on this newly provisioned, empty database and should be reassessed after representative workload data exists.
