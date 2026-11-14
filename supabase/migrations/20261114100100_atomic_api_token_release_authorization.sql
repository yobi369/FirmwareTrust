-- Revalidate scoped API-token authorization inside the same transaction as trusted release registration.
create or replace function private.register_verified_release_with_token(
  target_org uuid,target_project uuid,target_version text,target_artifact_name text,
  target_artifact_sha256 text,target_manifest jsonb,target_actor uuid,target_key_fingerprint text,
  target_manifest_sha256 text,target_signature_sha256 text,target_api_token_hash text default null
)
returns jsonb
language plpgsql
security definer
set search_path=pg_catalog,public,private
as $$
declare token_row public.api_tokens%rowtype;
begin
  if auth.role() is distinct from 'service_role' then
    raise exception 'Trusted registration service required' using errcode='42501';
  end if;
  if target_api_token_hash is not null then
    if target_api_token_hash !~ '^[a-f0-9]{64}$' then
      raise exception 'API token credential digest is malformed' using errcode='22023';
    end if;
    select * into token_row from public.api_tokens t
    where t.token_hash=target_api_token_hash
      and t.organization_id=target_org
      and t.revoked_at is null
      and t.expires_at>clock_timestamp()
      and t.scopes @> array['releases:write']::text[]
      and (cardinality(t.project_ids)=0 or target_project=any(t.project_ids))
    for share;
    if not found or token_row.created_by is distinct from target_actor then
      raise exception 'API token was revoked, expired or is outside its organization, project or scope' using errcode='42501';
    end if;
  end if;
  return private.register_verified_release(
    target_org,target_project,target_version,target_artifact_name,target_artifact_sha256,
    target_manifest,target_actor,target_key_fingerprint,target_manifest_sha256,target_signature_sha256
  );
end;
$$;

create or replace function public.register_verified_release_with_token(
  target_org uuid,target_project uuid,target_version text,target_artifact_name text,
  target_artifact_sha256 text,target_manifest jsonb,target_actor uuid,target_key_fingerprint text,
  target_manifest_sha256 text,target_signature_sha256 text,target_api_token_hash text default null
)
returns jsonb
language sql
security invoker
set search_path=pg_catalog,public,private
as $$
  select private.register_verified_release_with_token(
    target_org,target_project,target_version,target_artifact_name,target_artifact_sha256,
    target_manifest,target_actor,target_key_fingerprint,target_manifest_sha256,target_signature_sha256,
    target_api_token_hash
  );
$$;

revoke all on function private.register_verified_release_with_token(uuid,uuid,text,text,text,jsonb,uuid,text,text,text,text) from public,anon,authenticated;
grant execute on function private.register_verified_release_with_token(uuid,uuid,text,text,text,jsonb,uuid,text,text,text,text) to service_role;
revoke all on function public.register_verified_release_with_token(uuid,uuid,text,text,text,jsonb,uuid,text,text,text,text) from public,anon,authenticated;
grant execute on function public.register_verified_release_with_token(uuid,uuid,text,text,text,jsonb,uuid,text,text,text,text) to service_role;
