create or replace function private.is_org_creator(target_org uuid)
returns boolean language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.organizations o where o.id=target_org and o.created_by=auth.uid()); $$;
revoke all on function private.is_org_creator(uuid) from public,anon;
grant execute on function private.is_org_creator(uuid) to authenticated;
drop policy if exists "admins create memberships" on public.organization_memberships;
create policy "admins create memberships" on public.organization_memberships for insert to authenticated
with check(private.has_org_role(organization_id,array['owner','admin']) or (user_id=(select auth.uid()) and role='owner' and private.is_org_creator(organization_id)));
