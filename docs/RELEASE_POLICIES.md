# Release Policy Evaluation

**Status:** Database evaluator implemented; console authoring, approval collection and publication enforcement remain in progress.

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

Unknown rule keys and invalid types are rejected. Project-specific policies take precedence over organization-wide policies; within that scope the highest enabled version is selected.

## Evaluation API

Authenticated tenant members can call:

```http
POST /rest/v1/rpc/evaluate_release_policy
Content-Type: application/json
Authorization: Bearer <user-session>
apikey: <publishable-key>

{"target_release":"<release-uuid>"}
```

The function runs as `SECURITY INVOKER`, checks tenant membership, reads only rows visible through RLS and returns a deterministic `pass`, `block` or `no_policy` result with reasons and evidence counts. It does not publish a release or mutate release state.

## Important trust boundary

The `require_signed_manifest` rule currently checks that the stored manifest contains signature material and a registry scope. That database check is **not a cryptographic signature verification**. The authenticated `register-release` Edge Function is the component that verifies Ed25519 signatures and active registry-key status before accepting signed releases. Direct metadata-only drafts remain unsigned and must not be treated as verified releases.

Before a production release gate is enabled, the next implementation step is to make cryptographic verification attestations non-forgeable by direct table writes, then connect policy evaluation to an explicit approval/publish transaction. The evaluator is not itself a publish authorization endpoint.

## Validation

The authenticated SQL integration suite now asserts that a policy requiring a registry-scoped signed manifest, an SBOM, a complete scan and an independent approval blocks a release when those evidence conditions are absent. Additional positive-path and tampering tests remain required.
