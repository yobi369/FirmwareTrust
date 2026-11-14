# SBOM ingestion and vulnerability intelligence

## Supported input

The authenticated `POST /functions/v1/ingest-sbom` Edge Function accepts CycloneDX JSON and SPDX JSON documents. The Enterprise Console uploads the SBOM document only; firmware binaries are not uploaded.

- Maximum raw document size: 5 MB.
- Maximum normalized unique components: 20,000.
- CycloneDX root metadata component and nested components are included.
- SPDX package entries are normalized; package URLs are read from PURL external references.
- Components are deduplicated by package URL, name and version.
- The original parsed document is retained as JSONB, alongside a SHA-256 digest of the uploaded JSON text. Scan status, source, time, component count, finding count and any partial-scan warning are persisted on the SBOM record.
- The database RPC inserts the document, component inventory and `sbom.ingested` audit event atomically.

## Vulnerability enrichment

Components with versioned package URLs are queried against the public OSV.dev API:

1. `POST https://api.osv.dev/v1/querybatch` checks multiple package/version identifiers. OSV documents that response ordering corresponds to request ordering and that querybatch may return page tokens.
2. Querybatch results provide vulnerability identifiers and modification timestamps; the function hydrates advisory details with `GET https://api.osv.dev/v1/vulns/{id}`.
3. Findings are stored per affected component, with advisory ID, source, available severity, summary, affected range, fixed version and source modification timestamp.
4. Duplicate advisory/component records are ignored on re-ingestion.

Severity is not guessed. If the source does not provide a recognized severity, the finding is stored without one.

## Limits and scan status

- Up to 1,000 versioned PURLs are scanned per ingestion.
- Up to 500 distinct advisory details are hydrated per run.
- If OSV returns pagination tokens, a component/advisory cap is reached, or some detail lookups fail, the response reports `scan_status: partial`. It does not report a complete scan.
- If OSV is unavailable, the SBOM and component inventory remain saved and the response reports `scan_status: unavailable`.
- If no versioned PURLs are available, the response reports `scan_status: no_versioned_purls`.
- A successful OSV scan is vulnerability intelligence, not a guarantee that the firmware is safe or free of vulnerabilities.

## Authorization

The Edge Function requires a valid Supabase user JWT. The `ingest_sbom` database RPC is SECURITY INVOKER and checks the caller's organization role, project scope and optional release scope. RLS controls component and finding writes. Release-capable roles may ingest scan findings; triage/update/delete permissions remain restricted to security roles.

## Remaining hardening

The current implementation does not yet implement OSV pagination continuation, scheduled rescans, feed freshness alerts, vulnerability exceptions, approval gates, or a full false-positive/triage workflow. Those are separate delivery gates and must not be implied by an initial scan result.
