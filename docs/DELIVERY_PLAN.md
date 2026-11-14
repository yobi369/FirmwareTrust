# Enterprise Delivery Plan

This plan turns the FirmwareTrust feature set into testable delivery gates. Status is deliberately conservative: the dedicated backend and initial tenant schema are deployed; the first authenticated organization/project/release console is in preview and has not yet passed end-to-end security validation.

## Workstreams

### 1. Identity and organizations
- Configure a dedicated authentication/database project.
- Implement organization creation, membership, invitations and project ownership.
- Add role checks and tenant-isolation RLS policies.
- Test cross-tenant reads/writes, invitation expiry/replay and owner succession.

### 2. Registry and audit
- Register immutable release metadata and signed manifests.
- Add append-only audit events with per-organization hash chaining.
- Add release search, filters, export and verification history.
- Test idempotency, concurrent submissions and audit-chain integrity.

### 3. Key lifecycle
- Register public keys and fingerprints.
- Implement rotation, predecessor/successor relationships and revocation.
- Preserve historical signature evidence while surfacing current trust status.
- Test compromised-key response, clock boundaries and transition verification.

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

A dedicated Supabase project does not yet exist for FirmwareTrust. The connected Supabase organization discovered during setup is the user's existing organization `kupgmzealcvhuojopxkw`; it also contains unrelated application databases. Do not reuse those databases. Before provisioning, confirm that FirmwareTrust should have its own project under that organization. The project creation flow will surface any non-zero cost for approval.

The current Vercel deployment is a static M0 workbench. Hosted organization accounts, registry and API features must not be represented as active until the backend and deployment environment have been provisioned and tested.
