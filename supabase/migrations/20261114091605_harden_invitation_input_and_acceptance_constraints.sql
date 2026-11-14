alter table public.organization_invitations
  drop constraint organization_invitations_check1,
  add constraint organization_invitations_accepted_identity_consistent
  check (accepted_at is not null or accepted_by is null);

create or replace function private.create_organization_invitation(target_org uuid,target_email text,target_role text,expires_in_days integer default 7)
returns jsonb language plpgsql security definer set search_path=pg_catalog,public,private,extensions
as $$
declare actor uuid:=auth.uid(); normalized_email text:=lower(btrim(target_email)); raw_token text; invitation_id uuid; expiry timestamptz;
begin
  if actor is null then raise exception 'Authentication required' using errcode='28000'; end if;
  if not private.has_org_role(target_org,array['owner','admin']) then raise exception 'Only organization owners and admins can invite members' using errcode='42501'; end if;
  if normalized_email is null or normalized_email !~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' then raise exception 'A valid invitee email address is required' using errcode='22023'; end if;
  if target_role is null or target_role not in ('admin','release_manager','security_analyst','developer','viewer') then raise exception 'Invitation role is not permitted' using errcode='22023'; end if;
  if expires_in_days is null or expires_in_days<1 or expires_in_days>30 then raise exception 'Invitation expiry must be between 1 and 30 days' using errcode='22023'; end if;
  if exists(select 1 from public.organization_memberships m join auth.users u on u.id=m.user_id where m.organization_id=target_org and lower(u.email)=normalized_email) then
    raise exception 'This email already belongs to the organization' using errcode='23505'; end if;
  raw_token:=encode(gen_random_bytes(32),'hex'); expiry:=now()+make_interval(days=>expires_in_days);
  insert into public.organization_invitations(organization_id,email,role,token_hash,invited_by,expires_at)
  values(target_org,normalized_email,target_role,encode(extensions.digest(raw_token,'sha256'),'hex'),actor,expiry) returning id into invitation_id;
  perform private.record_system_audit_event(target_org,actor,'organization.invitation.created','organization_invitation',invitation_id::text,
    jsonb_build_object('email',normalized_email,'role',target_role,'expires_at',expiry));
  return jsonb_build_object('invitation_id',invitation_id,'email',normalized_email,'role',target_role,'expires_at',expiry,'token',raw_token);
end;
$$;
