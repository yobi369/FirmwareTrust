-- Organization invitations: hashed one-time tokens, role constraints, expiry and audited acceptance.
create table public.organization_invitations (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  email text not null check (email=lower(btrim(email)) and email ~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$'),
  role text not null check (role in ('admin','release_manager','security_analyst','developer','viewer')),
  token_hash text not null unique check (token_hash ~ '^[a-f0-9]{64}$'),
  invited_by uuid not null references auth.users(id) on delete restrict,
  expires_at timestamptz not null,
  accepted_at timestamptz,
  accepted_by uuid references auth.users(id) on delete set null,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  check (expires_at>created_at),
  check ((accepted_at is null)=(accepted_by is null)),
  check (accepted_at is null or revoked_at is null)
);
create unique index organization_invitations_one_pending_per_email on public.organization_invitations(organization_id,email)
where accepted_at is null and revoked_at is null;
create index organization_invitations_org_created on public.organization_invitations(organization_id,created_at desc);
alter table public.organization_invitations enable row level security;
create policy "owners and admins read organization invitations" on public.organization_invitations for select
using (private.has_org_role(organization_id,array['owner','admin']));
grant select on public.organization_invitations to authenticated;
revoke insert,update,delete,truncate,references,trigger on public.organization_invitations from anon,authenticated;

create or replace function private.guard_organization_invitation_mutation()
returns trigger language plpgsql set search_path=pg_catalog,public
as $$
begin
  if tg_op='DELETE' then raise exception 'Organization invitations cannot be deleted; revoke them instead'; end if;
  if (to_jsonb(new)-'accepted_at'-'accepted_by'-'revoked_at') is distinct from (to_jsonb(old)-'accepted_at'-'accepted_by'-'revoked_at') then
    raise exception 'Invitation identity, role, email, token hash and expiry are immutable'; end if;
  if old.accepted_at is not null or old.revoked_at is not null then raise exception 'Accepted or revoked invitations are immutable'; end if;
  if new.accepted_at is not null and new.revoked_at is not null then raise exception 'An invitation cannot be accepted and revoked'; end if;
  return new;
end;
$$;
create trigger organization_invitations_guard_update before update or delete on public.organization_invitations
for each row execute function private.guard_organization_invitation_mutation();

create or replace function private.create_organization_invitation(target_org uuid,target_email text,target_role text,expires_in_days integer default 7)
returns jsonb language plpgsql security definer set search_path=pg_catalog,public,private,extensions
as $$
declare actor uuid:=auth.uid(); normalized_email text:=lower(btrim(target_email)); raw_token text; invitation_id uuid; expiry timestamptz;
begin
  if actor is null then raise exception 'Authentication required' using errcode='28000'; end if;
  if not private.has_org_role(target_org,array['owner','admin']) then raise exception 'Only organization owners and admins can invite members' using errcode='42501'; end if;
  if normalized_email !~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' then raise exception 'A valid invitee email address is required' using errcode='22023'; end if;
  if target_role not in ('admin','release_manager','security_analyst','developer','viewer') then raise exception 'Invitation role is not permitted' using errcode='22023'; end if;
  if expires_in_days<1 or expires_in_days>30 then raise exception 'Invitation expiry must be between 1 and 30 days' using errcode='22023'; end if;
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

create or replace function private.accept_organization_invitation(invitation_token text)
returns jsonb language plpgsql security definer set search_path=pg_catalog,public,private,extensions
as $$
declare actor uuid:=auth.uid(); actor_email text:=lower(btrim(coalesce(auth.jwt()->>'email',''))); invite public.organization_invitations%rowtype; token_digest text;
begin
  if actor is null then raise exception 'Authentication required' using errcode='28000'; end if;
  if actor_email='' then raise exception 'Authenticated account email is unavailable' using errcode='28000'; end if;
  if invitation_token !~ '^[a-f0-9]{64}$' then raise exception 'Invitation token is invalid' using errcode='22023'; end if;
  token_digest:=encode(extensions.digest(invitation_token,'sha256'),'hex');
  select * into invite from public.organization_invitations i where i.token_hash=token_digest for update;
  if not found then raise exception 'Invitation is invalid or no longer available' using errcode='P0002'; end if;
  if invite.accepted_at is not null or invite.revoked_at is not null then raise exception 'Invitation has already been used or revoked' using errcode='23505'; end if;
  if invite.expires_at<=now() then raise exception 'Invitation has expired' using errcode='22023'; end if;
  if invite.email<>actor_email then raise exception 'Sign in with the email address this invitation was sent to' using errcode='42501'; end if;
  if exists(select 1 from public.organization_memberships m where m.organization_id=invite.organization_id and m.user_id=actor) then raise exception 'Your account is already a member of this organization' using errcode='23505'; end if;
  insert into public.organization_memberships(organization_id,user_id,role) values(invite.organization_id,actor,invite.role);
  update public.organization_invitations set accepted_at=now(),accepted_by=actor where id=invite.id;
  perform private.record_system_audit_event(invite.organization_id,actor,'organization.invitation.accepted','organization_invitation',invite.id::text,
    jsonb_build_object('email',invite.email,'role',invite.role));
  return jsonb_build_object('organization_id',invite.organization_id,'role',invite.role,'accepted',true);
end;
$$;

create or replace function private.revoke_organization_invitation(target_invitation uuid)
returns jsonb language plpgsql security definer set search_path=pg_catalog,public,private
as $$
declare actor uuid:=auth.uid(); invite public.organization_invitations%rowtype;
begin
  if actor is null then raise exception 'Authentication required' using errcode='28000'; end if;
  select * into invite from public.organization_invitations where id=target_invitation for update;
  if not found then raise exception 'Invitation not found' using errcode='P0002'; end if;
  if not private.has_org_role(invite.organization_id,array['owner','admin']) then raise exception 'Only organization owners and admins can revoke invitations' using errcode='42501'; end if;
  if invite.accepted_at is not null then raise exception 'An accepted invitation cannot be revoked'; end if;
  if invite.revoked_at is null then
    update public.organization_invitations set revoked_at=now() where id=invite.id;
    perform private.record_system_audit_event(invite.organization_id,actor,'organization.invitation.revoked','organization_invitation',invite.id::text,
      jsonb_build_object('email',invite.email,'role',invite.role));
  end if;
  return jsonb_build_object('invitation_id',invite.id,'revoked',true);
end;
$$;

create or replace function public.create_organization_invitation(target_org uuid,target_email text,target_role text,expires_in_days integer default 7)
returns jsonb language sql security invoker set search_path=pg_catalog,public,private
as $$ select private.create_organization_invitation(target_org,target_email,target_role,expires_in_days); $$;
create or replace function public.accept_organization_invitation(invitation_token text)
returns jsonb language sql security invoker set search_path=pg_catalog,public,private
as $$ select private.accept_organization_invitation(invitation_token); $$;
create or replace function public.revoke_organization_invitation(target_invitation uuid)
returns jsonb language sql security invoker set search_path=pg_catalog,public,private
as $$ select private.revoke_organization_invitation(target_invitation); $$;

revoke all on function private.guard_organization_invitation_mutation() from public,anon,authenticated;
revoke all on function private.create_organization_invitation(uuid,text,text,integer) from public,anon;
revoke all on function private.accept_organization_invitation(text) from public,anon;
revoke all on function private.revoke_organization_invitation(uuid) from public,anon;
grant execute on function private.create_organization_invitation(uuid,text,text,integer) to authenticated;
grant execute on function private.accept_organization_invitation(text) to authenticated;
grant execute on function private.revoke_organization_invitation(uuid) to authenticated;
revoke all on function public.create_organization_invitation(uuid,text,text,integer) from public,anon;
revoke all on function public.accept_organization_invitation(text) from public,anon;
revoke all on function public.revoke_organization_invitation(uuid) from public,anon;
grant execute on function public.create_organization_invitation(uuid,text,text,integer) to authenticated;
grant execute on function public.accept_organization_invitation(text) to authenticated;
grant execute on function public.revoke_organization_invitation(uuid) to authenticated;
