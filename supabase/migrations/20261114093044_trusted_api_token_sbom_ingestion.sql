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

create or replace function private.ingest_sbom_for_api_with_token(
 target_actor uuid,target_org uuid,target_project uuid,target_release uuid,target_format text,
 target_spec_version text,target_document_sha256 text,target_document jsonb,target_components jsonb,target_api_token_hash text
)
returns uuid language plpgsql security definer set search_path=pg_catalog,public,private
as $$
declare token_row public.api_tokens%rowtype;
begin
 if auth.role() is distinct from 'service_role' then raise exception 'Trusted API gateway service required' using errcode='42501'; end if;
 if target_api_token_hash is null or target_api_token_hash !~ '^[a-f0-9]{64}$' then raise exception 'API token credential digest is malformed' using errcode='22023'; end if;
 select * into token_row from public.api_tokens t where t.token_hash=target_api_token_hash and t.organization_id=target_org
  and t.revoked_at is null and t.expires_at>clock_timestamp() and t.scopes @> array['sboms:write']::text[]
  and (cardinality(t.project_ids)=0 or target_project=any(t.project_ids)) for share;
 if not found or token_row.created_by is distinct from target_actor then
  raise exception 'API token was revoked, expired or is outside its organization, project or SBOM scope' using errcode='42501';
 end if;
 return private.ingest_sbom_for_api(target_actor,target_org,target_project,target_release,target_format,target_spec_version,
  target_document_sha256,target_document,target_components);
end;
$$;
create or replace function public.ingest_sbom_for_api_with_token(
 target_actor uuid,target_org uuid,target_project uuid,target_release uuid,target_format text,
 target_spec_version text,target_document_sha256 text,target_document jsonb,target_components jsonb,target_api_token_hash text
)
returns uuid language sql security invoker set search_path=pg_catalog,public,private
as $$ select private.ingest_sbom_for_api_with_token(target_actor,target_org,target_project,target_release,target_format,
 target_spec_version,target_document_sha256,target_document,target_components,target_api_token_hash); $$;
revoke all on function private.ingest_sbom_for_api_with_token(uuid,uuid,uuid,uuid,text,text,text,jsonb,jsonb,text) from public,anon,authenticated;
grant execute on function private.ingest_sbom_for_api_with_token(uuid,uuid,uuid,uuid,text,text,text,jsonb,jsonb,text) to service_role;
revoke all on function public.ingest_sbom_for_api_with_token(uuid,uuid,uuid,uuid,text,text,text,jsonb,jsonb,text) from public,anon,authenticated;
grant execute on function public.ingest_sbom_for_api_with_token(uuid,uuid,uuid,uuid,text,text,text,jsonb,jsonb,text) to service_role;
