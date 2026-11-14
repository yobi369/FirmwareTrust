-- Signing-key lifecycle: public-key-only registration, atomic rotation and irreversible revocation.
create unique index if not exists signing_keys_one_active_fingerprint
  on public.signing_keys (organization_id, coalesce(project_id, '00000000-0000-0000-0000-000000000000'::uuid), key_fingerprint)
  where status = 'active';

create or replace function public.guard_signing_key_lifecycle()
returns trigger
language plpgsql
security invoker
set search_path = public
as $$
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;

  if tg_op = 'INSERT' then
    if new.created_by is distinct from auth.uid() then raise exception 'Key creator must be the authenticated user'; end if;
    if new.status <> 'active' or new.revoked_at is not null or new.revoked_reason is not null then
      raise exception 'New signing keys must begin active and not revoked';
    end if;
    if length(trim(new.key_fingerprint)) < 16 or length(trim(new.key_fingerprint)) > 256 then
      raise exception 'Invalid key fingerprint';
    end if;
    if length(trim(new.public_key_pem)) < 32 or length(new.public_key_pem) > 16384 then
      raise exception 'Public key PEM length is invalid';
    end if;
    if new.algorithm not in ('Ed25519', 'ECDSA-P256') then raise exception 'Unsupported signing-key algorithm'; end if;
    if new.rotated_from is not null and not exists (
      select 1 from public.signing_keys old_key
      where old_key.id = new.rotated_from and old_key.organization_id = new.organization_id
        and old_key.project_id is not distinct from new.project_id and old_key.status = 'rotated'
    ) then raise exception 'Replacement key must reference a rotated key in the same scope'; end if;
    return new;
  end if;

  if tg_op = 'UPDATE' then
    if new.organization_id is distinct from old.organization_id
      or new.project_id is distinct from old.project_id
      or new.key_fingerprint is distinct from old.key_fingerprint
      or new.algorithm is distinct from old.algorithm
      or new.public_key_pem is distinct from old.public_key_pem
      or new.created_by is distinct from old.created_by
      or new.created_at is distinct from old.created_at
      or new.valid_from is distinct from old.valid_from
      or new.rotated_from is distinct from old.rotated_from then
      raise exception 'Signing-key identity and public material are immutable';
    end if;
    if old.status <> 'active' then raise exception 'Only active signing keys may transition'; end if;
    if new.status not in ('rotated', 'revoked', 'expired') then raise exception 'Invalid signing-key lifecycle transition'; end if;
    if new.status = 'revoked' then
      if new.revoked_at is null then new.revoked_at := clock_timestamp(); end if;
      if new.revoked_reason is null or length(trim(new.revoked_reason)) < 3 then
        raise exception 'A meaningful revocation reason is required';
      end if;
    elsif new.revoked_at is not null or new.revoked_reason is not null then
      raise exception 'Revocation metadata is only valid for revoked keys';
    end if;
    if new.valid_until is null then new.valid_until := clock_timestamp(); end if;
    return new;
  end if;
  raise exception 'Signing keys cannot be deleted; revoke or rotate them instead';
end;
$$;

drop trigger if exists signing_key_lifecycle_guard on public.signing_keys;
create trigger signing_key_lifecycle_guard before insert or update or delete on public.signing_keys
for each row execute function public.guard_signing_key_lifecycle();

create or replace function public.rotate_signing_key(
  target_org uuid, old_key_id uuid, new_fingerprint text,
  new_public_key_pem text, new_algorithm text default 'Ed25519'
)
returns uuid language plpgsql security invoker set search_path = public
as $$
declare old_key public.signing_keys%rowtype; new_key_id uuid;
begin
  if auth.uid() is null or not public.has_org_role(target_org, array['owner','admin','security_analyst']) then
    raise exception 'Not authorized to rotate signing keys';
  end if;
  select * into old_key from public.signing_keys
  where id = old_key_id and organization_id = target_org and status = 'active' for update;
  if not found then raise exception 'Active signing key not found in this organization'; end if;
  update public.signing_keys set status = 'rotated', valid_until = clock_timestamp() where id = old_key.id;
  insert into public.signing_keys(organization_id,project_id,key_fingerprint,algorithm,public_key_pem,status,valid_from,rotated_from,created_by)
  values(old_key.organization_id,old_key.project_id,new_fingerprint,new_algorithm,new_public_key_pem,'active',clock_timestamp(),old_key.id,auth.uid())
  returning id into new_key_id;
  perform public.record_audit_event(target_org,'signing_key.rotated','signing_key',new_key_id::text,
    jsonb_build_object('previous_key_id',old_key.id,'new_key_id',new_key_id,'project_id',old_key.project_id,'algorithm',new_algorithm));
  return new_key_id;
end;
$$;

create or replace function public.revoke_signing_key(target_org uuid,target_key_id uuid,reason text)
returns void language plpgsql security invoker set search_path = public
as $$
declare revoked_key public.signing_keys%rowtype;
begin
  if auth.uid() is null or not public.has_org_role(target_org,array['owner','admin','security_analyst']) then
    raise exception 'Not authorized to revoke signing keys';
  end if;
  if reason is null or length(trim(reason)) < 3 or length(reason) > 1000 then
    raise exception 'Provide a revocation reason between 3 and 1000 characters';
  end if;
  update public.signing_keys set status='revoked',revoked_at=clock_timestamp(),revoked_reason=trim(reason)
  where id=target_key_id and organization_id=target_org and status='active'
  returning * into revoked_key;
  if not found then raise exception 'Active signing key not found in this organization'; end if;
  perform public.record_audit_event(target_org,'signing_key.revoked','signing_key',revoked_key.id::text,
    jsonb_build_object('key_fingerprint',revoked_key.key_fingerprint,'project_id',revoked_key.project_id,'reason',trim(reason)));
end;
$$;

revoke all on function public.rotate_signing_key(uuid,uuid,text,text,text) from public,anon;
revoke all on function public.revoke_signing_key(uuid,uuid,text) from public,anon;
grant execute on function public.rotate_signing_key(uuid,uuid,text,text,text) to authenticated;
grant execute on function public.revoke_signing_key(uuid,uuid,text) to authenticated;
