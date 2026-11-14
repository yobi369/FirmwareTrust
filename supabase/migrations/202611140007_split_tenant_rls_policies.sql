drop policy if exists "admins manage api tokens" on public.api_tokens;
create policy "admins read api tokens" on public.api_tokens for select to authenticated using(private.has_org_role(organization_id,array['owner','admin']));
create policy "admins create api tokens" on public.api_tokens for insert to authenticated with check(private.has_org_role(organization_id,array['owner','admin']));
create policy "admins update api tokens" on public.api_tokens for update to authenticated using(private.has_org_role(organization_id,array['owner','admin'])) with check(private.has_org_role(organization_id,array['owner','admin']));
create policy "admins delete api tokens" on public.api_tokens for delete to authenticated using(private.has_org_role(organization_id,array['owner','admin']));

drop policy if exists "owners admins manage memberships" on public.organization_memberships;
drop policy if exists "creator bootstraps first owner" on public.organization_memberships;
create policy "admins create memberships" on public.organization_memberships for insert to authenticated with check(private.has_org_role(organization_id,array['owner','admin']) or (user_id=(select auth.uid()) and role='owner' and exists(select 1 from public.organizations o where o.id=organization_id and o.created_by=(select auth.uid()))));
create policy "admins update memberships" on public.organization_memberships for update to authenticated using(private.has_org_role(organization_id,array['owner','admin'])) with check(private.has_org_role(organization_id,array['owner','admin']));
create policy "admins delete memberships" on public.organization_memberships for delete to authenticated using(private.has_org_role(organization_id,array['owner','admin']));

drop policy if exists "admins manage projects" on public.projects;
create policy "admins create projects" on public.projects for insert to authenticated with check(private.has_org_role(organization_id,array['owner','admin']));
create policy "admins update projects" on public.projects for update to authenticated using(private.has_org_role(organization_id,array['owner','admin'])) with check(private.has_org_role(organization_id,array['owner','admin']));
create policy "admins delete projects" on public.projects for delete to authenticated using(private.has_org_role(organization_id,array['owner','admin']));

drop policy if exists "admins manage policies" on public.release_policies;
create policy "admins create policies" on public.release_policies for insert to authenticated with check(private.has_org_role(organization_id,array['owner','admin']));
create policy "admins update policies" on public.release_policies for update to authenticated using(private.has_org_role(organization_id,array['owner','admin'])) with check(private.has_org_role(organization_id,array['owner','admin']));
create policy "admins delete policies" on public.release_policies for delete to authenticated using(private.has_org_role(organization_id,array['owner','admin']));

drop policy if exists "release roles manage releases" on public.releases;
create policy "release roles create releases" on public.releases for insert to authenticated with check(private.has_org_role(organization_id,array['owner','admin','release_manager','developer']));
create policy "release roles update releases" on public.releases for update to authenticated using(private.has_org_role(organization_id,array['owner','admin','release_manager','developer'])) with check(private.has_org_role(organization_id,array['owner','admin','release_manager','developer']));
create policy "release roles delete releases" on public.releases for delete to authenticated using(private.has_org_role(organization_id,array['owner','admin','release_manager','developer']));

drop policy if exists "release roles manage sboms" on public.sbom_documents;
create policy "release roles create sboms" on public.sbom_documents for insert to authenticated with check(private.has_org_role(organization_id,array['owner','admin','release_manager','developer','security_analyst']));
create policy "release roles update sboms" on public.sbom_documents for update to authenticated using(private.has_org_role(organization_id,array['owner','admin','release_manager','developer','security_analyst'])) with check(private.has_org_role(organization_id,array['owner','admin','release_manager','developer','security_analyst']));
create policy "release roles delete sboms" on public.sbom_documents for delete to authenticated using(private.has_org_role(organization_id,array['owner','admin','release_manager','developer','security_analyst']));

drop policy if exists "security roles manage signing keys" on public.signing_keys;
create policy "security roles create signing keys" on public.signing_keys for insert to authenticated with check(private.has_org_role(organization_id,array['owner','admin','security_analyst']));
create policy "security roles update signing keys" on public.signing_keys for update to authenticated using(private.has_org_role(organization_id,array['owner','admin','security_analyst'])) with check(private.has_org_role(organization_id,array['owner','admin','security_analyst']));
create policy "security roles delete signing keys" on public.signing_keys for delete to authenticated using(private.has_org_role(organization_id,array['owner','admin','security_analyst']));

drop policy if exists "security roles manage findings" on public.vulnerability_findings;
create policy "security roles create findings" on public.vulnerability_findings for insert to authenticated with check(private.has_org_role(organization_id,array['owner','admin','security_analyst']));
create policy "security roles update findings" on public.vulnerability_findings for update to authenticated using(private.has_org_role(organization_id,array['owner','admin','security_analyst'])) with check(private.has_org_role(organization_id,array['owner','admin','security_analyst']));
create policy "security roles delete findings" on public.vulnerability_findings for delete to authenticated using(private.has_org_role(organization_id,array['owner','admin','security_analyst']));

drop policy if exists "admins manage webhook endpoints" on public.webhook_endpoints;
create policy "admins read webhook endpoints" on public.webhook_endpoints for select to authenticated using(private.has_org_role(organization_id,array['owner','admin']));
create policy "admins create webhook endpoints" on public.webhook_endpoints for insert to authenticated with check(private.has_org_role(organization_id,array['owner','admin']));
create policy "admins update webhook endpoints" on public.webhook_endpoints for update to authenticated using(private.has_org_role(organization_id,array['owner','admin'])) with check(private.has_org_role(organization_id,array['owner','admin']));
create policy "admins delete webhook endpoints" on public.webhook_endpoints for delete to authenticated using(private.has_org_role(organization_id,array['owner','admin']));
