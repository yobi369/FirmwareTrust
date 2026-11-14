-- Reject private keys, non-Ed25519 PEMs and caller-supplied fingerprints that do not match the public key bytes.
create or replace function public.guard_signing_key_lifecycle()
returns trigger
language plpgsql
security invoker
set search_path = public
as $$
declare
  pem_body text;
  der_bytes bytea;
  raw_public_key bytea;
  calculated_fingerprint text;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  if tg_op = 'INSERT' then
    if new.created_by is distinct from auth.uid() then
      raise exception 'Key creator must be the authenticated user';
    end if;
    if new.status <> 'active' or new.revoked_at is not null or new.revoked_reason is not null then
      raise exception 'New signing keys must begin active and not revoked';
    end if;
    if length(trim(new.key_fingerprint)) <> 16 or new.key_fingerprint !~ '^[a-fA-F0-9]{16}$' then
      raise exception 'Invalid M0-compatible signing-key fingerprint';
    end if;
    if length(trim(new.public_key_pem)) < 64 or length(new.public_key_pem) > 16384 then
      raise exception 'Public key PEM length is invalid';
    end if;
    if new.algorithm <> 'Ed25519' then
      raise exception 'Only Ed25519 keys are currently supported for release verification';
    end if;
    if new.public_key_pem !~ '^-----BEGIN PUBLIC KEY-----[[:space:]]+[A-Za-z0-9+/=[:space:]]+-----END PUBLIC KEY-----[[:space:]]*$'
       or position('PRIVATE KEY' in upper(new.public_key_pem)) > 0 then
      raise exception 'Only a PEM-encoded PUBLIC KEY is accepted; private keys are never accepted';
    end if;

    pem_body := regexp_replace(new.public_key_pem,
      '^-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|[[:space:]]', '', 'g');
    begin
      der_bytes := decode(pem_body, 'base64');
    exception when others then
      raise exception 'Public key PEM contains invalid base64';
    end;

    if octet_length(der_bytes) <> 44
       or substring(der_bytes from 1 for 12) <> decode('302a300506032b6570032100', 'hex') then
      raise exception 'Public key must be an Ed25519 SubjectPublicKeyInfo key';
    end if;

    raw_public_key := substring(der_bytes from 13 for 32);
    calculated_fingerprint := left(encode(extensions.digest(raw_public_key, 'sha256'), 'hex'), 16);
    if lower(new.key_fingerprint) is distinct from calculated_fingerprint then
      raise exception 'Public key fingerprint does not match the Ed25519 public key material';
    end if;
    new.key_fingerprint := calculated_fingerprint;

    if new.rotated_from is not null and not exists (
      select 1 from public.signing_keys old_key
      where old_key.id = new.rotated_from
        and old_key.organization_id = new.organization_id
        and old_key.project_id is not distinct from new.project_id
        and old_key.status = 'rotated'
    ) then
      raise exception 'Replacement key must reference a rotated key in the same scope';
    end if;
    return new;
  elsif tg_op = 'UPDATE' then
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
    if old.status <> 'active' then
      raise exception 'Only active signing keys may transition';
    end if;
    if new.status not in ('rotated', 'revoked', 'expired') then
      raise exception 'Invalid signing-key lifecycle transition';
    end if;
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