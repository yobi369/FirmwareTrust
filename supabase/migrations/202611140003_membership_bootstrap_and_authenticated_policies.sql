-- Fix initial organization owner bootstrap and scope RLS policies to signed-in users.
create or replace function public.guard_membership_changes()
returns trigger language plpgsql security definer set search_path = public
as $$
declare actor_role text; remaining_owners integer; creator uuid;
begin
  select role into actor_role from public.organization_memberships
  where organization_id = coalesce(new.organization_id,old.organization_id)
    and user_id = auth.uid();
  if tg_op = 'INSERT' then
    if actor_role is null then
      select created_by into creator from public.organizations where id = new.organization_id;
      if creator = auth.uid() and new.role = 'owner' then return new; end if;
    end if;
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
      if remaining_owners = 0 then raise exception 'An organization must retain at least one owner'; end if;
    end if;
    return old;
  end if;
  return null;
end;
$$;

alter policy "members read organizations" on public.organizations to authenticated;
alter policy "members read memberships" on public.organization_memberships to authenticated;
alter policy "owners admins manage memberships" on public.organization_memberships to authenticated;
alter policy "members read projects" on public.projects to authenticated;
alter policy "admins manage projects" on public.projects to authenticated;
alter policy "members read releases" on public.releases to authenticated;
alter policy "release roles manage releases" on public.releases to authenticated;
alter policy "members read signing keys" on public.signing_keys to authenticated;
alter policy "security roles manage signing keys" on public.signing_keys to authenticated;
alter policy "members read sboms" on public.sbom_documents to authenticated;
alter policy "release roles manage sboms" on public.sbom_documents to authenticated;
alter policy "members read components" on public.sbom_components to authenticated;
alter policy "members read findings" on public.vulnerability_findings to authenticated;
alter policy "security roles manage findings" on public.vulnerability_findings to authenticated;
alter policy "members read policies" on public.release_policies to authenticated;
alter policy "admins manage policies" on public.release_policies to authenticated;
alter policy "members read approvals" on public.release_approvals to authenticated;
alter policy "reviewers create approvals" on public.release_approvals to authenticated;
alter policy "admins manage api tokens" on public.api_tokens to authenticated;
alter policy "admins manage webhook endpoints" on public.webhook_endpoints to authenticated;
alter policy "members read webhook deliveries" on public.webhook_deliveries to authenticated;
alter policy "members read audit events" on public.audit_events to authenticated;
