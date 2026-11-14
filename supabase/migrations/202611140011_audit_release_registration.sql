-- Every release registration is audited in the same transaction as the release row.
create or replace function private.audit_release_registration()
returns trigger
language plpgsql
security definer
set search_path = public, private
as $$
begin
  if auth.uid() is null or new.created_by is distinct from auth.uid() then
    raise exception 'Release creator must be the authenticated user';
  end if;

  perform private.record_audit_event(
    new.organization_id,
    'release.registered',
    'release',
    new.id::text,
    jsonb_build_object(
      'project_id', new.project_id,
      'version', new.version,
      'artifact_name', new.artifact_name,
      'artifact_sha256', new.artifact_sha256,
      'status', new.status
    )
  );
  return new;
end;
$$;

revoke all on function private.audit_release_registration() from public, anon;
drop trigger if exists releases_audit_registration on public.releases;
create trigger releases_audit_registration
after insert on public.releases
for each row execute function private.audit_release_registration();