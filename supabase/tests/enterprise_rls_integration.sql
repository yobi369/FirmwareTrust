-- Disposable authenticated integration test. Run as database owner in a transaction; all fixtures are rolled back.
begin;

insert into auth.users(id,aud,role,email,created_at,updated_at)
values
  ('f1000000-0000-4000-8000-000000000001','authenticated','authenticated','ft-test-owner@example.invalid',now(),now()),
  ('f1000000-0000-4000-8000-000000000002','authenticated','authenticated','ft-test-outsider@example.invalid',now(),now()),
  ('f1000000-0000-4000-8000-000000000003','authenticated','authenticated','ft-test-developer@example.invalid',now(),now())
on conflict (id) do nothing;

set local role authenticated;

do $$
declare
  owner_id uuid := 'f1000000-0000-4000-8000-000000000001';
  outsider_id uuid := 'f1000000-0000-4000-8000-000000000002';
  developer_id uuid := 'f1000000-0000-4000-8000-000000000003';
  org_a uuid;
  org_b uuid;
  key_a uuid;
  key_b uuid;
  n integer;
begin
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  org_a := public.create_organization('FirmwareTrust Test Org','ft-test-org-rls-20261114');
  if not exists(select 1 from public.organization_memberships where organization_id=org_a and user_id=owner_id and role='owner') then
    raise exception 'FAIL: creator did not become first owner';
  end if;

  insert into public.signing_keys(organization_id,key_fingerprint,algorithm,public_key_pem,status,created_by)
  values(org_a,'fttestfingerprint0001','Ed25519','-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----','active',owner_id)
  returning id into key_a;

  insert into public.organization_memberships(organization_id,user_id,role)
  values(org_a,developer_id,'developer');

  begin
    insert into public.signing_keys(organization_id,key_fingerprint,algorithm,public_key_pem,status,created_by)
    values(org_a,'fttestfingerprint0001','Ed25519','-----BEGIN PUBLIC KEY-----\nZHVwbA==\n-----END PUBLIC KEY-----','active',owner_id);
    raise exception 'FAIL: duplicate active fingerprint was accepted';
  exception when unique_violation then null;
  end;

  begin
    update public.signing_keys set public_key_pem='-----BEGIN PUBLIC KEY-----\nY2hhbmdlZA==\n-----END PUBLIC KEY-----' where id=key_a;
    raise exception 'FAIL: immutable public key material was changed';
  exception when raise_exception then
    if sqlerrm like 'FAIL:%' then raise; end if;
    if sqlerrm not like '%immutable%' then raise; end if;
  end;

  key_b := public.rotate_signing_key(org_a,key_a,'fttestfingerprint0002','-----BEGIN PUBLIC KEY-----\nZmFrZTI=\n-----END PUBLIC KEY-----','Ed25519');
  if not exists(select 1 from public.signing_keys where id=key_a and status='rotated') then
    raise exception 'FAIL: predecessor not marked rotated';
  end if;
  if not exists(select 1 from public.signing_keys where id=key_b and status='active' and rotated_from=key_a) then
    raise exception 'FAIL: successor not active or linked';
  end if;

  perform public.revoke_signing_key(org_a,key_b,'integration test revocation');
  if not exists(select 1 from public.signing_keys where id=key_b and status='revoked' and revoked_at is not null) then
    raise exception 'FAIL: revocation not persisted';
  end if;

  perform set_config('request.jwt.claim.sub',developer_id::text,true);
  begin
    perform public.revoke_signing_key(org_a,key_a,'developer must not revoke keys');
    raise exception 'FAIL: developer role revoked a signing key';
  exception when raise_exception then
    if sqlerrm like 'FAIL:%' then raise; end if;
    if sqlerrm not like '%Not authorized%' then raise; end if;
  end;
  begin
    insert into public.signing_keys(organization_id,key_fingerprint,algorithm,public_key_pem,status,created_by)
    values(org_a,'fttestfingerprint0003','Ed25519','-----BEGIN PUBLIC KEY-----\nZGV2\n-----END PUBLIC KEY-----','active',developer_id);
    raise exception 'FAIL: developer role registered a signing key';
  exception when insufficient_privilege then null;
  end;

  perform set_config('request.jwt.claim.sub',outsider_id::text,true);
  select count(*) into n from public.organizations where id=org_a;
  if n <> 0 then raise exception 'FAIL: cross-tenant organization read exposed % rows',n; end if;
  begin
    perform public.revoke_signing_key(org_a,key_b,'outsider must not revoke');
    raise exception 'FAIL: non-member revoked another tenant key';
  exception when raise_exception then
    if sqlerrm like 'FAIL:%' then raise; end if;
    if sqlerrm not like '%Not authorized%' then raise; end if;
  end;

  org_b := public.create_organization('FirmwareTrust Outsider Org','ft-test-org-outsider-20261114');
  if not exists(select 1 from public.organization_memberships where organization_id=org_b and user_id=outsider_id and role='owner') then
    raise exception 'FAIL: second creator bootstrap failed';
  end if;

  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  select count(*) into n from public.organizations where id=org_b;
  if n <> 0 then raise exception 'FAIL: reverse cross-tenant read exposed % rows',n; end if;

  if exists (
    select 1
    from (
      select previous_hash, lag(event_hash) over (order by id) as prior_hash
      from public.audit_events
      where organization_id=org_a
    ) chain
    where prior_hash is not null and previous_hash is distinct from prior_hash
  ) then
    raise exception 'FAIL: audit hash chain continuity check failed';
  end if;
end $$;

rollback;
