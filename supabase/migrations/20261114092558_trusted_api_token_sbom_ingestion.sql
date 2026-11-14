-- Trusted API-token SBOM ingestion reuses the authenticated tenant ingestion validator.
create or replace function private.ingest_sbom_for_api(
  target_actor uuid,target_org uuid,target_project uuid,target_release uuid,target_format text,
  target_spec_version text,target_document_sha256 text,target_document jsonb,target_components jsonb
)
returns uuid language plpgsql security definer set search_path=pg_catalog,public,private
as $$
declare result_id uuid;
begin
  if auth.role() is distinct from 'service_role' then raise exception 'Trusted API gateway service required' using errcode='42501'; end if;
  if target_actor is null or not exists(select 1 from public.organization_memberships m where m.organization_id=target_org and m.user_id=target_actor and m.role in ('owner','admin','release_manager','developer','security_analyst')) then
    raise exception 'API token creator is no longer authorized to ingest SBOMs' using errcode='42501'; end if;
  perform set_config('request.jwt.claim.sub',target_actor::text,true);
  perform set_config('request.jwt.claims',jsonb_build_object('sub',target_actor::text)::text,true);
  result_id:=public.ingest_sbom(target_org,target_project,target_release,target_format,target_spec_version,target_document_sha256,target_document,target_components);
  return result_id;
end;
$$;
create or replace function public.ingest_sbom_for_api(
  target_actor uuid,target_org uuid,target_project uuid,target_release uuid,target_format text,
  target_spec_version text,target_document_sha256 text,target_document jsonb,target_components jsonb
)
returns uuid language sql security invoker set search_path=pg_catalog,public,private
as $$ select private.ingest_sbom_for_api(target_actor,target_org,target_project,target_release,target_format,target_spec_version,target_document_sha256,target_document,target_components); $$;
revoke all on function private.ingest_sbom_for_api(uuid,uuid,uuid,uuid,text,text,text,jsonb,jsonb) from public,anon,authenticated;
grant execute on function private.ingest_sbom_for_api(uuid,uuid,uuid,uuid,text,text,text,jsonb,jsonb) to service_role;
revoke all on function public.ingest_sbom_for_api(uuid,uuid,uuid,uuid,text,text,text,jsonb,jsonb) from public,anon,authenticated;
grant execute on function public.ingest_sbom_for_api(uuid,uuid,uuid,uuid,text,text,text,jsonb,jsonb) to service_role;
