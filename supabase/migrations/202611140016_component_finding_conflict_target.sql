-- Use a non-partial unique index so PostgREST on_conflict can target the component-scoped identity.
drop index if exists public.vulnerability_findings_sbom_advisory_source_component_key;
drop index if exists public.vulnerability_findings_sbom_advisory_source_unlinked_key;
create unique index vulnerability_findings_sbom_advisory_source_component_key
  on public.vulnerability_findings(sbom_id,advisory_id,source,component_id);