-- Allow release-capable members to ingest normalized SBOM components and scan findings.
drop policy if exists "release roles create components" on public.sbom_components;
create policy "release roles create components"
on public.sbom_components
for insert
to authenticated
with check (
  exists (
    select 1
    from public.sbom_documents s
    where s.id = sbom_id
      and private.has_org_role(s.organization_id, array['owner','admin','release_manager','developer','security_analyst'])
  )
);

drop policy if exists "security roles create findings" on public.vulnerability_findings;
create policy "release roles create findings"
on public.vulnerability_findings
for insert
to authenticated
with check (
  private.has_org_role(organization_id, array['owner','admin','release_manager','developer','security_analyst'])
);

create or replace function public.ingest_sbom(
  target_org uuid,
  target_project uuid,
  target_release uuid,
  target_format text,
  target_spec_version text,
  target_document_sha256 text,
  target_document jsonb,
  target_components jsonb
)
returns uuid
language plpgsql
security invoker
set search_path = public, private
as $$
declare
  actor_id uuid := auth.uid();
  new_sbom_id uuid;
  component_count integer;
begin
  if actor_id is null then raise exception 'Authentication required'; end if;
  if not private.has_org_role(target_org, array['owner','admin','release_manager','developer','security_analyst']) then
    raise exception 'Not authorized to ingest SBOMs for this organization';
  end if;
  if not exists(select 1 from public.projects p where p.id=target_project and p.organization_id=target_org) then
    raise exception 'Project does not belong to the selected organization';
  end if;
  if target_release is not null and not exists(
    select 1 from public.releases r where r.id=target_release and r.organization_id=target_org and r.project_id=target_project
  ) then
    raise exception 'Release does not belong to the selected project';
  end if;
  if target_format not in ('cyclonedx','spdx') then raise exception 'Unsupported SBOM format'; end if;
  if target_document_sha256 !~ '^[a-f0-9]{64}$' then raise exception 'Invalid SBOM document SHA-256'; end if;
  if target_document is null or pg_column_size(target_document) > 10485760 then raise exception 'SBOM document is missing or too large'; end if;
  if jsonb_typeof(target_components) <> 'array' then raise exception 'SBOM components must be a JSON array'; end if;
  component_count := jsonb_array_length(target_components);
  if component_count < 1 or component_count > 20000 then raise exception 'SBOM must contain between 1 and 20000 components'; end if;
  if exists (
    select 1 from jsonb_to_recordset(target_components) as c(component_name text, version text, purl text, license_expression text, hashes jsonb)
    where component_name is null or length(trim(component_name)) < 1 or length(component_name) > 512
      or (version is not null and length(version) > 255)
      or (purl is not null and length(purl) > 2048)
      or (license_expression is not null and length(license_expression) > 2048)
      or (hashes is not null and jsonb_typeof(hashes) <> 'object')
  ) then
    raise exception 'SBOM contains an invalid component record';
  end if;

  insert into public.sbom_documents(organization_id,project_id,release_id,format,spec_version,document_sha256,document,source)
  values(target_org,target_project,target_release,target_format,nullif(target_spec_version,''),target_document_sha256,target_document,'upload')
  returning id into new_sbom_id;

  insert into public.sbom_components(sbom_id,component_name,version,purl,license_expression,hashes)
  select new_sbom_id,trim(c.component_name),nullif(trim(c.version),''),nullif(trim(c.purl),''),
    nullif(trim(c.license_expression),''),coalesce(c.hashes,'{}'::jsonb)
  from jsonb_to_recordset(target_components) as c(component_name text, version text, purl text, license_expression text, hashes jsonb);

  perform private.record_audit_event(
    target_org,
    'sbom.ingested',
    'sbom_document',
    new_sbom_id::text,
    jsonb_build_object('project_id',target_project,'release_id',target_release,'format',target_format,'component_count',component_count,'document_sha256',target_document_sha256)
  );

  return new_sbom_id;
end;
$$;

revoke all on function public.ingest_sbom(uuid,uuid,uuid,text,text,text,jsonb,jsonb) from public, anon;
grant execute on function public.ingest_sbom(uuid,uuid,uuid,text,text,text,jsonb,jsonb) to authenticated;