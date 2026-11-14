-- Keep first-owner bootstrap narrow and private: only the creator can create an organization and its initial owner membership.
create or replace function private.bootstrap_organization(org_name text, org_slug text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  actor_id uuid := auth.uid();
  new_org_id uuid;
  normalized_slug text := lower(trim(org_slug));
begin
  if actor_id is null then
    raise exception 'Authentication required';
  end if;
  if org_name is null or length(trim(org_name)) < 2 or length(trim(org_name)) > 120 then
    raise exception 'Organization name must be between 2 and 120 characters';
  end if;
  if normalized_slug is null or length(normalized_slug) < 2 or length(normalized_slug) > 63
     or normalized_slug !~ '^[a-z0-9]+(-[a-z0-9]+)*$' then
    raise exception 'Organization slug must be 2-63 lowercase letters, numbers or hyphens';
  end if;

  insert into public.organizations(name, slug, created_by)
  values (trim(org_name), normalized_slug, actor_id)
  returning id into new_org_id;

  insert into public.organization_memberships(organization_id, user_id, role)
  values (new_org_id, actor_id, 'owner');

  perform private.record_audit_event(
    new_org_id,
    'organization.created',
    'organization',
    new_org_id::text,
    jsonb_build_object('name', trim(org_name), 'slug', normalized_slug)
  );

  return new_org_id;
end;
$$;

revoke all on function private.bootstrap_organization(text, text) from public, anon;
grant execute on function private.bootstrap_organization(text, text) to authenticated;

create or replace function public.create_organization(org_name text, org_slug text)
returns uuid
language sql
security invoker
set search_path = public, private
as $$
  select private.bootstrap_organization(org_name, org_slug);
$$;

revoke all on function public.create_organization(text, text) from public, anon;
grant execute on function public.create_organization(text, text) to authenticated;
