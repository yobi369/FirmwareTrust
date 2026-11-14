# Release Policy Evaluation

**Status:** Version-pinned policy evaluation and independent approval workflow implemented; publication remains blocked pending non-forgeable cryptographic verification attestations.

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

The `require_signed_manifest` rule currently checks that the stored manifest contains signature material and a registry scope. That database check is **not a cryptographic signature verification**. The authenticated `register-release` Edge Function is the component that verifies Ed25519 signatures and active registry-key status before accepting signed releases. Direct metadata-only drafts remain unsigned and must not be treated as verified releases.

Release review is now an explicit workflow: an owner/admin/release manager requests review; the database pins the applicable policy version; an independent owner/admin/release manager/security analyst records one immutable decision; the evaluator enforces quorum and evidence before the release can become `approved`. The release identity, artifact digest, manifest and pinned policy cannot be changed after review begins. Approval decisions and status transitions are appended to the audit chain. Direct status updates cannot bypass the same policy checks.

**Publication is intentionally disabled.** An `approved` release cannot transition to `published` until the system binds the Edge Function's cryptographic signature verification result to a non-forgeable server-side attestation that direct authenticated table writes cannot fabricate. The current policy evaluator checks manifest signature/scope declarations only; it does not independently verify Ed25519.

## Validation

The authenticated SQL integration suite covers policy blocking, pinned policy review, independent reviewer decisions, duplicate-decision rejection, audit insertion, direct status-bypass rejection and release-evidence immutability. The latest expanded integration run still needs a successful execution after the new review workflow changes.
