-- Move SECURITY DEFINER helpers out of the exposed PostgREST schema.
create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated;

create or replace function private.has_org_role(target_org uuid, allowed_roles text[])
returns boolean language sql stable security definer set search_path = public
as $$ select exists (select 1 from public.organization_memberships m where m.organization_id=target_org and m.user_id=auth.uid() and m.role=any(allowed_roles)); $$;
create or replace function private.is_org_member(target_org uuid)
returns boolean language sql stable security definer set search_path = public
as $$ select exists (select 1 from public.organization_memberships m where m.organization_id=target_org and m.user_id=auth.uid()); $$;
revoke all on function private.has_org_role(uuid,text[]) from public,anon;
revoke all on function private.is_org_member(uuid) from public,anon;
grant execute on function private.has_org_role(uuid,text[]) to authenticated;
grant execute on function private.is_org_member(uuid) to authenticated;

do $$
declare p record; using_expr text; check_expr text; stmt text;
begin
 for p in select schemaname,tablename,policyname,qual,with_check from pg_policies
 where schemaname='public' and ((qual is not null and (qual like '%has_org_role(%' or qual like '%is_org_member(%')) or (with_check is not null and (with_check like '%has_org_role(%' or with_check like '%is_org_member(%')))
 loop
  stmt:=format('alter policy %I on %I.%I',p.policyname,p.schemaname,p.tablename);
  if p.qual is not null then using_expr:=replace(replace(p.qual,'has_org_role(','private.has_org_role('),'is_org_member(','private.is_org_member(');stmt:=stmt||format(' using (%s)',using_expr);end if;
  if p.with_check is not null then check_expr:=replace(replace(p.with_check,'has_org_role(','private.has_org_role('),'is_org_member(','private.is_org_member(');stmt:=stmt||format(' with check (%s)',check_expr);end if;
  execute stmt;
 end loop;
end $$;

drop policy if exists "creator creates organization" on public.organizations;
create policy "creator creates organization" on public.organizations for insert to authenticated with check (created_by=(select auth.uid()));
drop policy if exists "creator bootstraps first owner" on public.organization_memberships;
create policy "creator bootstraps first owner" on public.organization_memberships for insert to authenticated
with check(user_id=(select auth.uid()) and role='owner' and exists(select 1 from public.organizations o where o.id=organization_id and o.created_by=(select auth.uid())));

create or replace function public.create_organization(org_name text,org_slug text)
returns uuid language plpgsql security invoker set search_path=public
as $$ declare new_org_id uuid; begin
 if auth.uid() is null then raise exception 'Authentication required'; end if;
 insert into public.organizations(name,slug,created_by) values(org_name,lower(org_slug),auth.uid()) returning id into new_org_id;
 insert into public.organization_memberships(organization_id,user_id,role) values(new_org_id,auth.uid(),'owner');
 return new_org_id;
end $$;
revoke all on function public.create_organization(text,text) from public,anon;
grant execute on function public.create_organization(text,text) to authenticated;

create or replace function private.record_audit_event(target_org uuid,event_action text,event_resource_type text,event_resource_id text default null,event_metadata jsonb default '{}'::jsonb)
returns bigint language plpgsql security definer set search_path=public,extensions
as $$ declare prev text;next_hash text;new_id bigint;occurred timestamptz:=clock_timestamp();begin
 if auth.uid() is null or not private.has_org_role(target_org,array['owner','admin','release_manager','security_analyst','developer']) then raise exception 'Not authorized to append audit events';end if;
 perform pg_advisory_xact_lock(hashtext(target_org::text));
 select event_hash into prev from public.audit_events where organization_id=target_org order by id desc limit 1;
 next_hash:=encode(digest(coalesce(prev,'')||'|'||target_org::text||'|'||auth.uid()::text||'|'||event_action||'|'||event_resource_type||'|'||coalesce(event_resource_id,'')||'|'||coalesce(event_metadata,'{}'::jsonb)::text||'|'||occurred::text,'sha256'),'hex');
 insert into public.audit_events(organization_id,actor_id,action,resource_type,resource_id,metadata,previous_hash,event_hash,occurred_at)
 values(target_org,auth.uid(),event_action,event_resource_type,event_resource_id,coalesce(event_metadata,'{}'::jsonb),prev,next_hash,occurred) returning id into new_id;
 return new_id;
end $$;
revoke all on function private.record_audit_event(uuid,text,text,text,jsonb) from public,anon;
grant execute on function private.record_audit_event(uuid,text,text,text,jsonb) to authenticated;

create or replace function public.rotate_signing_key(target_org uuid,old_key_id uuid,new_fingerprint text,new_public_key_pem text,new_algorithm text default 'Ed25519')
returns uuid language plpgsql security invoker set search_path=public,private
as $$ declare old_key public.signing_keys%rowtype;new_key_id uuid;begin
 if auth.uid() is null or not private.has_org_role(target_org,array['owner','admin','security_analyst']) then raise exception 'Not authorized to rotate signing keys';end if;
 select * into old_key from public.signing_keys where id=old_key_id and organization_id=target_org and status='active' for update;
 if not found then raise exception 'Active signing key not found in this organization';end if;
 update public.signing_keys set status='rotated',valid_until=clock_timestamp() where id=old_key.id;
 insert into public.signing_keys(organization_id,project_id,key_fingerprint,algorithm,public_key_pem,status,valid_from,rotated_from,created_by)
 values(old_key.organization_id,old_key.project_id,new_fingerprint,new_algorithm,new_public_key_pem,'active',clock_timestamp(),old_key.id,auth.uid()) returning id into new_key_id;
 perform private.record_audit_event(target_org,'signing_key.rotated','signing_key',new_key_id::text,jsonb_build_object('previous_key_id',old_key.id,'new_key_id',new_key_id,'project_id',old_key.project_id,'algorithm',new_algorithm));
 return new_key_id;
end $$;
create or replace function public.revoke_signing_key(target_org uuid,target_key_id uuid,reason text)
returns void language plpgsql security invoker set search_path=public,private
as $$ declare revoked_key public.signing_keys%rowtype;begin
 if auth.uid() is null or not private.has_org_role(target_org,array['owner','admin','security_analyst']) then raise exception 'Not authorized to revoke signing keys';end if;
 if reason is null or length(trim(reason))<3 or length(reason)>1000 then raise exception 'Provide a revocation reason between 3 and 1000 characters';end if;
 update public.signing_keys set status='revoked',revoked_at=clock_timestamp(),revoked_reason=trim(reason) where id=target_key_id and organization_id=target_org and status='active' returning * into revoked_key;
 if not found then raise exception 'Active signing key not found in this organization';end if;
 perform private.record_audit_event(target_org,'signing_key.revoked','signing_key',revoked_key.id::text,jsonb_build_object('key_fingerprint',revoked_key.key_fingerprint,'project_id',revoked_key.project_id,'reason',trim(reason)));
end $$;

drop function if exists public.has_org_role(uuid,text[]);
drop function if exists public.is_org_member(uuid);
drop function if exists public.record_audit_event(uuid,text,text,text,jsonb);
