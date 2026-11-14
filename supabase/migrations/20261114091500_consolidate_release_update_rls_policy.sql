drop policy if exists "security analysts advance reviewed release state" on public.releases;
drop policy if exists "release roles update releases" on public.releases;
create policy "release roles update releases"
on public.releases for update
using (private.has_org_role(organization_id,array['owner','admin','release_manager','developer','security_analyst']))
with check (private.has_org_role(organization_id,array['owner','admin','release_manager','developer','security_analyst']));
