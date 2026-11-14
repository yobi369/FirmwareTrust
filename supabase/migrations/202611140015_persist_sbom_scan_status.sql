alter table public.sbom_documents
  add column if not exists scan_status text not null default 'pending'
    check (scan_status in ('pending','complete','partial','unavailable','no_versioned_purls','not_started')),
  add column if not exists scan_source text,
  add column if not exists scanned_at timestamptz,
  add column if not exists scanned_component_count integer not null default 0 check (scanned_component_count >= 0),
  add column if not exists finding_count integer not null default 0 check (finding_count >= 0),
  add column if not exists scan_warning text;