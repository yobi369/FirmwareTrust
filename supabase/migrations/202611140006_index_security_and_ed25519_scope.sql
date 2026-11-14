create index if not exists idx_api_tokens_created_by on public.api_tokens(created_by);
create index if not exists idx_audit_events_actor on public.audit_events(actor_id);
create index if not exists idx_organizations_created_by on public.organizations(created_by);
create index if not exists idx_projects_created_by on public.projects(created_by);
create index if not exists idx_release_approvals_policy on public.release_approvals(policy_id);
create index if not exists idx_release_approvals_reviewer on public.release_approvals(reviewer_id);
create index if not exists idx_release_policies_created_by on public.release_policies(created_by);
create index if not exists idx_release_policies_org_project on public.release_policies(organization_id,project_id);
create index if not exists idx_releases_created_by on public.releases(created_by);
create index if not exists idx_sbom_documents_org_project_release on public.sbom_documents(organization_id,project_id,release_id);
create index if not exists idx_signing_keys_created_by on public.signing_keys(created_by);
create index if not exists idx_signing_keys_org_project on public.signing_keys(organization_id,project_id);
create index if not exists idx_signing_keys_rotated_from on public.signing_keys(rotated_from);
create index if not exists idx_vulnerability_findings_component on public.vulnerability_findings(component_id);
create index if not exists idx_vulnerability_findings_org_sbom on public.vulnerability_findings(organization_id,sbom_id);
create index if not exists idx_webhook_endpoints_created_by on public.webhook_endpoints(created_by);
alter policy "reviewers create approvals" on public.release_approvals with check (reviewer_id=(select auth.uid()) and private.has_org_role(organization_id,array['owner','admin','release_manager','security_analyst']));
create or replace function public.guard_signing_key_lifecycle()
returns trigger language plpgsql security invoker set search_path=public
as $$
begin
 if auth.uid() is null then raise exception 'Authentication required';end if;
 if tg_op='INSERT' then
  if new.created_by is distinct from auth.uid() then raise exception 'Key creator must be the authenticated user';end if;
  if new.status<>'active' or new.revoked_at is not null or new.revoked_reason is not null then raise exception 'New signing keys must begin active and not revoked';end if;
  if length(trim(new.key_fingerprint))<16 or length(trim(new.key_fingerprint))>256 then raise exception 'Invalid key fingerprint';end if;
  if length(trim(new.public_key_pem))<32 or length(new.public_key_pem)>16384 then raise exception 'Public key PEM length is invalid';end if;
  if new.algorithm<>'Ed25519' then raise exception 'Only Ed25519 keys are currently supported for release verification';end if;
  if new.rotated_from is not null and not exists(select 1 from public.signing_keys old_key where old_key.id=new.rotated_from and old_key.organization_id=new.organization_id and old_key.project_id is not distinct from new.project_id and old_key.status='rotated') then raise exception 'Replacement key must reference a rotated key in the same scope';end if;
  return new;
 elsif tg_op='UPDATE' then
  if new.organization_id is distinct from old.organization_id or new.project_id is distinct from old.project_id or new.key_fingerprint is distinct from old.key_fingerprint or new.algorithm is distinct from old.algorithm or new.public_key_pem is distinct from old.public_key_pem or new.created_by is distinct from old.created_by or new.created_at is distinct from old.created_at or new.valid_from is distinct from old.valid_from or new.rotated_from is distinct from old.rotated_from then raise exception 'Signing-key identity and public material are immutable';end if;
  if old.status<>'active' then raise exception 'Only active signing keys may transition';end if;
  if new.status not in ('rotated','revoked','expired') then raise exception 'Invalid signing-key lifecycle transition';end if;
  if new.status='revoked' then if new.revoked_at is null then new.revoked_at:=clock_timestamp();end if;if new.revoked_reason is null or length(trim(new.revoked_reason))<3 then raise exception 'A meaningful revocation reason is required';end if;
  elsif new.revoked_at is not null or new.revoked_reason is not null then raise exception 'Revocation metadata is only valid for revoked keys';end if;
  if new.valid_until is null then new.valid_until:=clock_timestamp();end if;
  return new;
 end if;
 raise exception 'Signing keys cannot be deleted; revoke or rotate them instead';
end;
$$;
