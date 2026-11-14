# Release Policy Evaluation

**Status:** Version-pinned policy evaluation, independent approvals, non-forgeable server-side verification attestations and a policy-gated publication transaction implemented. End-to-end deployment and runtime verification remain pending.

## Supported versioned policy rules

A policy is a JSON object stored in `release_policies.rules`. The current evaluator accepts only:

| Rule | Type | Meaning |
|---|---|---|
| `require_signed_manifest` | boolean | Require a manifest that declares a signature and FirmwareTrust organization/project registry scope |
| `require_sbom` | boolean | Require at least one SBOM associated with the release or project |
| `require_complete_sbom_scan` | boolean | Require every associated SBOM scan to have status `complete` |
| `block_on_critical` | boolean | Block if any associated component has a critical finding |
| `max_high_findings` | integer ≥ 0 | Block when high-severity findings exceed this limit |
| `min_approvals` | integer ≥ 0 | Require this many distinct independent approvals for this policy version |

Unknown rule keys and invalid types are rejected. Project-specific policies take precedence over organization-wide policies. Within the selected scope, the most recently created enabled policy is selected; version numbers are monotonic within each policy name. Once a release enters review, its exact policy row is pinned and cannot be changed.

## Evaluation API

Authenticated tenant members can call:

```http
POST /rest/v1/rpc/evaluate_release_policy
Content-Type: application/json
Authorization: Bearer <user-session>
apikey: <publishable-key>

{"target_release":"<release-uuid>"}
```

The function runs as `SECURITY INVOKER`, checks tenant membership, reads only rows visible through RLS and returns a deterministic `pass`, `block` or `no_policy` result with reasons and evidence counts. `no_policy` is a blocking result for approval. Once a review request is created, the selected policy ID is pinned to that release so later policy versions cannot silently change the review criteria.

## Important trust boundary

The `require_signed_manifest` rule now requires a row in `release_verification_attestations` matching the release, tenant scope and manifest key ID. The authenticated `register-release` Edge Function verifies the Ed25519 signature and active registry-key status, then calls a service-role-only database RPC that atomically creates the release and attestation. Direct metadata-only drafts cannot create attestations and cannot pass this rule.

Release review is now an explicit workflow: an owner/admin/release manager requests review; the database pins the applicable policy version; an independent owner/admin/release manager/security analyst records one immutable decision; the evaluator enforces quorum and evidence before the release can become `approved`. The release identity, artifact digest, manifest and pinned policy cannot be changed after review begins. Approval decisions and status transitions are appended to the audit chain. Direct status updates cannot bypass the same policy checks.

Publication now requires an approved release, a matching immutable server-created attestation and a fresh passing policy evaluation. The `publish_release` SECURITY INVOKER RPC performs the transaction, while a database trigger repeats the authorization and evidence checks so direct status updates cannot bypass the gate. The attestation is trusted because only the authenticated Edge Function's service-role registration path can create it; the secret key is never sent to the browser.

## Validation

The authenticated SQL integration suite covers policy blocking, pinned policy review, independent reviewer decisions, duplicate-decision rejection, audit insertion, direct status-bypass rejection and release-evidence immutability. The expanded review-workflow SQL assertions still need a successful post-change execution. End-to-end Edge Function tests must verify that a valid signed manifest creates an attestation, while tampered signatures, revoked keys, cross-tenant requests and direct authenticated attestation inserts fail.
