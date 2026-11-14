-- Scoped, one-time-visible API tokens with hashed-at-rest credentials.
alter table public.api_tokens
  add column if not exists project_ids uuid[] not null default '{}'::uuid[];

alter table public.api_tokens
  add constraint api_tokens_scopes_valid
  check (
    cardinality(scopes) between 1 and 5
    and scopes <@ array['releases:write','releases:read','sboms:write','keys:read','audit:read']::text[]
  );

alter table public.api_tokens
  add constraint api_tokens_project_ids_bounded
  check (cardinality(project_ids) <= 100);

create index if not exists idx_api_tokens_project_ids on public.api_tokens using gin(project_ids);

drop policy if exists "admins create api tokens" on public.api_tokens;
drop policy if exists "admins delete api tokens" on public.api_tokens;
drop policy if exists "admins update api tokens" on public.api_tokens;
drop policy if exists "admins manage api tokens" on public.api_tokens;
drop policy if exists "admins read api tokens" on public.api_tokens;
create policy "admins read api tokens" on public.api_tokens
for select to authenticated
using (private.has_org_role(organization_id,array['owner','admin']));

revoke all on table public.api_tokens from public,anon,authenticated;
grant select (
  id,organization_id,name,token_prefix,scopes,project_ids,last_used_at,
  expires_at,revoked_at,created_by,created_at
) on public.api_tokens to authenticated;
grant update(last_used_at) on public.api_tokens to service_role;

create or replace function private.guard_api_token_mutation()
returns trigger language plpgsql
set search_path=pg_catalog
as $$
begin
  if tg_op='DELETE' then
    raise exception 'API tokens cannot be deleted; revoke them instead';
  end if;
  if new.id is distinct from old.id
    or new.organization_id is distinct from old.organization_id
    or new.name is distinct from old.name
    or new.token_prefix is distinct from old.token_prefix
    or new.token_hash is distinct from old.token_hash
    or new.scopes is distinct from old.scopes
    or new.project_ids is distinct from old.project_ids
    or new.expires_at is distinct from old.expires_at
    or new.created_by is distinct from old.created_by
    or new.created_at is distinct from old.created_at then
    raise exception 'API token identity, secret hash, scope and expiry are immutable';
  end if;
  if old.revoked_at is not null and new.revoked_at is distinct from old.revoked_at then
    raise exception 'API token revocation is irreversible';
  end if;
  if old.last_used_at is not null and new.last_used_at is not null and new.last_used_at < old.last_used_at then
    raise exception 'API token last-used time cannot move backwards';
  end if;
  return new;
end;
$$;
drop trigger if exists api_tokens_immutable on public.api_tokens;
create trigger api_tokens_immutable
before update or delete on public.api_tokens
for each row execute function private.guard_api_token_mutation();

create or replace function private.create_api_token(
  target_org uuid,target_name text,target_scopes text[],target_project_ids uuid[],target_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path=pg_catalog,public,private,extensions
as $$
declare
  secret_value text;
  token_id uuid;
  token_prefix_value text;
  now_value timestamptz:=clock_timestamp();
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode='28000'; end if;
  if not private.has_org_role(target_org,array['owner','admin']) then
    raise exception 'Only organization owners and admins can create API tokens' using errcode='42501';
  end if;
  if target_name is null or length(trim(target_name)) not between 3 and 80 then
    raise exception 'API token name must contain 3 to 80 characters' using errcode='22023';
  end if;
  if target_scopes is null or cardinality(target_scopes) not between 1 and 5
    or exists(select 1 from unnest(target_scopes) as s(scope_name)
      where s.scope_name not in ('releases:write','releases:read','sboms:write','keys:read','audit:read'))
    or cardinality(target_scopes)<>(select count(distinct scope_name)::integer from unnest(target_scopes) as s(scope_name)) then
    raise exception 'API token scopes are invalid or duplicated' using errcode='22023';
  end if;
  if target_project_ids is null then target_project_ids:='{}'::uuid[]; end if;
  if cardinality(target_project_ids)<>(select count(distinct project_id)::integer from unnest(target_project_ids) as p(project_id)) then
    raise exception 'API token project scope contains duplicates' using errcode='22023';
  end if;
  if cardinality(target_project_ids)>0 and
    (select count(*) from public.projects p where p.organization_id=target_org and p.id=any(target_project_ids))<>cardinality(target_project_ids) then
    raise exception 'Every API token project must belong to the selected organization' using errcode='22023';
  end if;
  if target_expires_at is null or target_expires_at<=now_value or target_expires_at>now_value+interval '365 days' then
    raise exception 'API tokens must expire within the next 365 days' using errcode='22023';
  end if;

  secret_value:='ft_live_'||rtrim(translate(encode(extensions.gen_random_bytes(32),'base64'),'+/','-_'),'=');
  token_prefix_value:=left(secret_value,16);
  insert into public.api_tokens(organization_id,name,token_prefix,token_hash,scopes,project_ids,expires_at,created_by)
  values(target_org,trim(target_name),token_prefix_value,
    encode(extensions.digest(convert_to(secret_value,'utf8'),'sha256'),'hex'),
    target_scopes,target_project_ids,target_expires_at,auth.uid())
  returning id into token_id;

  perform private.record_audit_event(target_org,'api_token.created','api_token',token_id::text,
    jsonb_build_object('name',trim(target_name),'prefix',token_prefix_value,'scopes',to_jsonb(target_scopes),
      'project_ids',to_jsonb(target_project_ids),'expires_at',target_expires_at));

  return jsonb_build_object('id',token_id,'token',secret_value,'token_prefix',token_prefix_value,
    'scopes',to_jsonb(target_scopes),'project_ids',to_jsonb(target_project_ids),
    'expires_at',target_expires_at,'created_at',now_value);
end;
$$;

create or replace function private.revoke_api_token(target_org uuid,target_token_id uuid)
returns jsonb
language plpgsql
security definer
set search_path=pg_catalog,public,private
as $$
declare token_row public.api_tokens%rowtype;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode='28000'; end if;
  if not private.has_org_role(target_org,array['owner','admin']) then
    raise exception 'Only organization owners and admins can revoke API tokens' using errcode='42501';
  end if;
  select * into token_row from public.api_tokens
  where id=target_token_id and organization_id=target_org for update;
  if not found then raise exception 'API token not found' using errcode='P0002'; end if;
  if token_row.revoked_at is not null then
    return jsonb_build_object('id',token_row.id,'status','already_revoked','revoked_at',token_row.revoked_at);
  end if;
  update public.api_tokens set revoked_at=clock_timestamp() where id=token_row.id returning * into token_row;
  perform private.record_audit_event(target_org,'api_token.revoked','api_token',token_row.id::text,
    jsonb_build_object('name',token_row.name,'prefix',token_row.token_prefix));
  return jsonb_build_object('id',token_row.id,'status','revoked','revoked_at',token_row.revoked_at);
end;
$$;

create or replace function public.create_api_token(
  target_org uuid,target_name text,target_scopes text[],target_project_ids uuid[] default '{}'::uuid[],
  target_expires_at timestamptz default (now()+interval '90 days')
)
returns jsonb
language sql
security invoker
set search_path=pg_catalog,public,private
as $$
  select private.create_api_token(target_org,target_name,target_scopes,target_project_ids,target_expires_at);
$$;

create or replace function public.revoke_api_token(target_org uuid,target_token_id uuid)
returns jsonb
language sql
security invoker
set search_path=pg_catalog,public,private
as $$
  select private.revoke_api_token(target_org,target_token_id);
$$;

revoke all on function private.guard_api_token_mutation() from public,anon,authenticated,service_role;
revoke all on function private.create_api_token(uuid,text,text[],uuid[],timestamptz) from public,anon;
revoke all on function private.revoke_api_token(uuid,uuid) from public,anon;
grant execute on function private.create_api_token(uuid,text,text[],uuid[],timestamptz) to authenticated;
grant execute on function private.revoke_api_token(uuid,uuid) to authenticated;
revoke all on function public.create_api_token(uuid,text,text[],uuid[],timestamptz) from public,anon;
revoke all on function public.revoke_api_token(uuid,uuid) from public,anon;
grant execute on function public.create_api_token(uuid,text,text[],uuid[],timestamptz) to authenticated;
grant execute on function public.revoke_api_token(uuid,uuid) to authenticated;
