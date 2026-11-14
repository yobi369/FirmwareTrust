-- Restore SBOM ingestion as a supported token scope in the issuance function.
create or replace function private.create_api_token(target_org uuid,target_name text,target_scopes text[],target_project_ids uuid[],target_expires_at timestamptz)
returns jsonb language plpgsql security definer set search_path=pg_catalog,public,private,extensions
as $$
declare secret_value text; token_id uuid; token_prefix_value text; now_value timestamptz:=clock_timestamp();
begin
 if auth.uid() is null then raise exception 'Authentication required' using errcode='28000'; end if;
 if not private.has_org_role(target_org,array['owner','admin']) then raise exception 'Only organization owners and admins can create API tokens' using errcode='42501'; end if;
 if target_name is null or length(trim(target_name)) not between 3 and 80 then raise exception 'API token name must contain 3 to 80 characters' using errcode='22023'; end if;
 if target_scopes is null or cardinality(target_scopes) not between 1 and 5
  or exists(select 1 from unnest(target_scopes) as s(scope_name) where s.scope_name not in ('releases:write','releases:read','sboms:write','keys:read','audit:read'))
  or cardinality(target_scopes)<>(select count(distinct scope_name)::integer from unnest(target_scopes) as s(scope_name)) then
  raise exception 'API token scopes are invalid or duplicated' using errcode='22023'; end if;
 if target_project_ids is null then target_project_ids:='{}'::uuid[]; end if;
 if cardinality(target_project_ids)>100 or cardinality(target_project_ids)<>(select count(distinct project_id)::integer from unnest(target_project_ids) as p(project_id)) then
  raise exception 'API token project scope is invalid or duplicated' using errcode='22023'; end if;
 if cardinality(target_project_ids)>0 and (select count(*) from public.projects p where p.organization_id=target_org and p.id=any(target_project_ids))<>cardinality(target_project_ids) then
  raise exception 'Every API token project must belong to the selected organization' using errcode='22023'; end if;
 if target_expires_at is null or target_expires_at<=now_value or target_expires_at>now_value+interval '365 days' then
  raise exception 'API tokens must expire within the next 365 days' using errcode='22023'; end if;
 secret_value:='ft_live_'||rtrim(translate(encode(extensions.gen_random_bytes(32),'base64'),'+/','-_'),'=');
 token_prefix_value:=left(secret_value,16);
 insert into public.api_tokens(organization_id,name,token_prefix,token_hash,scopes,project_ids,expires_at,created_by)
 values(target_org,trim(target_name),token_prefix_value,encode(extensions.digest(convert_to(secret_value,'utf8'),'sha256'),'hex'),target_scopes,target_project_ids,target_expires_at,auth.uid())
 returning id into token_id;
 perform private.record_audit_event(target_org,'api_token.created','api_token',token_id::text,jsonb_build_object('name',trim(target_name),'prefix',token_prefix_value,'scopes',to_jsonb(target_scopes),'project_ids',to_jsonb(target_project_ids),'expires_at',target_expires_at));
 return jsonb_build_object('id',token_id,'token',secret_value,'token_prefix',token_prefix_value,'scopes',to_jsonb(target_scopes),'project_ids',to_jsonb(target_project_ids),'expires_at',target_expires_at,'created_at',now_value);
end;
$$;
