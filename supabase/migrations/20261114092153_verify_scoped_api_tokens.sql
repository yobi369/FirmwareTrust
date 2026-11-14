-- Token introspection validates bearer secrets, scope, project restriction and expiry.
create or replace function private.verify_api_token(raw_token text,required_scope text,target_project uuid default null)
returns jsonb language plpgsql security definer
set search_path=pg_catalog,public,private,extensions
as $$
declare token_row public.api_tokens%rowtype; token_digest text; now_value timestamptz:=clock_timestamp();
begin
  if raw_token is null or raw_token !~ '^ft_live_[A-Za-z0-9_-]{43}$' then raise exception 'API token is invalid, expired or revoked' using errcode='28000'; end if;
  if required_scope is null or required_scope not in ('releases:write','releases:read','sboms:write','keys:read','audit:read') then raise exception 'Requested API scope is invalid' using errcode='22023'; end if;
  token_digest:=encode(extensions.digest(convert_to(raw_token,'utf8'),'sha256'),'hex');
  select * into token_row from public.api_tokens t where t.token_hash=token_digest for update;
  if not found or token_row.revoked_at is not null or token_row.expires_at is null or token_row.expires_at<=now_value then raise exception 'API token is invalid, expired or revoked' using errcode='28000'; end if;
  if not required_scope=any(token_row.scopes) then raise exception 'API token does not grant the required scope' using errcode='42501'; end if;
  if cardinality(token_row.project_ids)>0 and (target_project is null or not target_project=any(token_row.project_ids)) then raise exception 'API token is not authorized for the requested project' using errcode='42501'; end if;
  update public.api_tokens set last_used_at=now_value where id=token_row.id;
  return jsonb_build_object('token_id',token_row.id,'organization_id',token_row.organization_id,'created_by',token_row.created_by,
    'scopes',to_jsonb(token_row.scopes),'project_ids',to_jsonb(token_row.project_ids),'expires_at',token_row.expires_at);
end;
$$;
create or replace function public.verify_api_token(raw_token text,required_scope text,target_project uuid default null)
returns jsonb language sql security invoker set search_path=pg_catalog,public,private
as $$ select private.verify_api_token(raw_token,required_scope,target_project); $$;
revoke all on function private.verify_api_token(text,text,uuid) from public;
grant execute on function private.verify_api_token(text,text,uuid) to anon,authenticated;
revoke all on function public.verify_api_token(text,text,uuid) from public;
grant execute on function public.verify_api_token(text,text,uuid) to anon,authenticated;
