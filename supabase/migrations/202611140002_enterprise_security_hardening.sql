-- FirmwareTrust enterprise security hardening
-- Tightens owner succession, tenant-consistent foreign keys, approval separation,
-- audit hash chaining, function execution and query indexes.

create or replace function public.prevent_audit_mutation()
returns trigger language plpgsql
set search_path = pg_catalog
as $$ begin raise exception 'Audit events are append-only'; end; $$;

revoke all on function public.create_organization(text,text) from public, anon;
revoke all on function public.is_org_member(uuid) from public, anon;
revoke all on function public.has_org_role(uuid,text[]) from public, anon;
grant execute on function public.create_organization(text,text) to authenticated;
grant execute on function public.is_org_member(uuid) to authenticated;
grant execute on function public.has_org_role(uuid,text[]) to authenticated;

create or replace function public.guard_membership_changes()
returns trigger language plpgsql security definer set search_path = public
as $$
declare actor_role text; remaining_owners integer;
begin
  select role into actor_role from public.organization_memberships
  where organization_id = coalesce(new.organization_id,old.organization_id)
    and user_id = auth.uid();
  if tg_op = 'INSERT' then
    if new.role = 'owner' and actor_role is distinct from 'owner' then
      raise exception 'Only an existing owner may appoint another owner';
    end if;
    return new;
  elsif tg_op = 'UPDATE' then
    if old.role = 'owner' and actor_role is distinct from 'owner' then
      raise exception 'Only an owner may modify an owner membership';
    end if;
    if new.role = 'owner' and actor_role is distinct from 'owner' then
      raise exception 'Only an owner may appoint another owner';
    end if;
    return new;
  elsif tg_op = 'DELETE' then
    if old.role = 'owner' and actor_role is distinct from 'owner' then
      raise exception 'Only an owner may remove an owner membership';
    end if;
    if old.role = 'owner' then
      select count(*) into remaining_owners from public.organization_memberships
      where organization_id = old.organization_id and role = 'owner'
        and user_id <> old.user_id;
      if remaining_owners = 0 then
        raise exception 'An organization must retain at least one owner';
      end if;
    end if;
    return old;
  end if;
  return null;
end;
$$;
drop trigger if exists organization_membership_guard on public.organization_memberships;
create trigger organization_membership_guard before insert or update or delete
on public.organization_memberships for each row execute function public.guard_membership_changes();
revoke all on function public.guard_membership_changes() from public, anon, authenticated;

alter table public.releases
  add constraint releases_org_id_id_unique unique (organization_id,id),
  add constraint releases_org_project_id_id_unique unique (organization_id,project_id,id);
alter table public.sbom_documents
  add constraint sbom_documents_org_id_id_unique unique (organization_id,id);
alter table public.sbom_documents drop constraint if exists sbom_documents_release_id_fkey;
alter table public.sbom_documents add constraint sbom_release_same_tenant_project_fk
  foreign key (organization_id,project_id,release_id)
  references public.releases(organization_id,project_id,id) on delete set null (release_id);
alter table public.release_approvals drop constraint if exists release_approvals_release_id_fkey;
alter table public.release_approvals add constraint release_approvals_same_org_release_fk
  foreign key (organization_id,release_id)
  references public.releases(organization_id,id) on delete cascade;
alter table public.vulnerability_findings drop constraint if exists vulnerability_findings_sbom_id_fkey;
alter table public.vulnerability_findings add constraint vulnerability_findings_same_org_sbom_fk
  foreign key (organization_id,sbom_id)
  references public.sbom_documents(organization_id,id) on delete cascade;

drop policy if exists "admins append audit events" on public.audit_events;
create or replace function public.record_audit_event(
  target_org uuid,event_action text,event_resource_type text,
  event_resource_id text default null,event_metadata jsonb default '{}'::jsonb
)
returns bigint language plpgsql security definer set search_path = public, extensions
as $$
declare prev text; next_hash text; new_id bigint; occurred timestamptz := clock_timestamp();
begin
  if auth.uid() is null or not public.has_org_role(target_org,
    array['owner','admin','release_manager','security_analyst','developer']) then
    raise exception 'Not authorized to append audit events';
  end if;
  perform pg_advisory_xact_lock(hashtext(target_org::text));
  select event_hash into prev from public.audit_events
    where organization_id = target_org order by id desc limit 1;
  next_hash := encode(digest(
    coalesce(prev,'') || '|' || target_org::text || '|' || auth.uid()::text || '|' ||
    event_action || '|' || event_resource_type || '|' || coalesce(event_resource_id,'') ||
    '|' || coalesce(event_metadata,'{}'::jsonb)::text || '|' || occurred::text,'sha256'),'hex');
  insert into public.audit_events(organization_id,actor_id,action,resource_type,
    resource_id,metadata,previous_hash,event_hash,occurred_at)
  values(target_org,auth.uid(),event_action,event_resource_type,event_resource_id,
    coalesce(event_metadata,'{}'::jsonb),prev,next_hash,occurred) returning id into new_id;
  return new_id;
end;
$$;
revoke all on function public.record_audit_event(uuid,text,text,text,jsonb) from public, anon;
grant execute on function public.record_audit_event(uuid,text,text,text,jsonb) to authenticated;

create or replace function public.guard_release_approval()
returns trigger language plpgsql set search_path = public
as $$
declare creator uuid; release_org uuid;
begin
  select created_by,organization_id into creator,release_org
  from public.releases where id = new.release_id;
  if release_org is distinct from new.organization_id then
    raise exception 'Approval and release must belong to the same organization';
  end if;
  if creator = new.reviewer_id then
    raise exception 'Release authors cannot approve their own releases';
  end if;
  return new;
end;
$$;
drop trigger if exists release_approval_separation on public.release_approvals;
create trigger release_approval_separation before insert on public.release_approvals
for each row execute function public.guard_release_approval();
revoke all on function public.guard_release_approval() from public, anon, authenticated;

create index if not exists idx_memberships_user on public.organization_memberships(user_id,organization_id);
create index if not exists idx_projects_org on public.projects(organization_id,created_at desc);
create index if not exists idx_releases_org_created on public.releases(organization_id,created_at desc);
create index if not exists idx_releases_project on public.releases(project_id,created_at desc);
create index if not exists idx_signing_keys_org_status on public.signing_keys(organization_id,status);
create index if not exists idx_sbom_documents_org_project on public.sbom_documents(organization_id,project_id,ingested_at desc);
create index if not exists idx_sbom_components_sbom on public.sbom_components(sbom_id);
create index if not exists idx_findings_org_severity on public.vulnerability_findings(organization_id,severity,observed_at desc);
create index if not exists idx_release_approvals_org_release on public.release_approvals(organization_id,release_id);
create index if not exists idx_api_tokens_org on public.api_tokens(organization_id);
create index if not exists idx_webhook_endpoints_org on public.webhook_endpoints(organization_id);
create index if not exists idx_webhook_deliveries_org on public.webhook_deliveries(organization_id,created_at desc);
create index if not exists idx_audit_events_org_id on public.audit_events(organization_id,id desc);
