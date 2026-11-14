-- Disposable authenticated integration test. Run as database owner in a transaction; all fixtures are rolled back.
begin;

insert into auth.users(id,aud,role,email,created_at,updated_at)
values
  ('f1000000-0000-4000-8000-000000000001','authenticated','authenticated','ft-test-owner@example.invalid',now(),now()),
  ('f1000000-0000-4000-8000-000000000002','authenticated','authenticated','ft-test-outsider@example.invalid',now(),now()),
  ('f1000000-0000-4000-8000-000000000003','authenticated','authenticated','ft-test-developer@example.invalid',now(),now()),
  ('f1000000-0000-4000-8000-000000000004','authenticated','authenticated','ft-test-reviewer@example.invalid',now(),now()),
  ('f1000000-0000-4000-8000-000000000005','authenticated','authenticated','ft-test-invitee@example.invalid',now(),now())
on conflict (id) do nothing;

set local role authenticated;

do $$
declare
  owner_id uuid := 'f1000000-0000-4000-8000-000000000001';
  outsider_id uuid := 'f1000000-0000-4000-8000-000000000002';
  developer_id uuid := 'f1000000-0000-4000-8000-000000000003';
  reviewer_user_id uuid := 'f1000000-0000-4000-8000-000000000004';
  invitee_id uuid := 'f1000000-0000-4000-8000-000000000005';
  invite_token text;
  invitation_id uuid;
  invitation_result jsonb;
  raw_a bytea := decode('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f','hex');
  raw_b bytea := decode('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f','hex');
  raw_c bytea := decode('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f','hex');
  pem_a text := '-----BEGIN PUBLIC KEY-----' || E'\n' || encode(decode('302a300506032b6570032100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f','hex'),'base64') || E'\n-----END PUBLIC KEY-----';
  pem_b text := '-----BEGIN PUBLIC KEY-----' || E'\n' || encode(decode('302a300506032b6570032100202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f','hex'),'base64') || E'\n-----END PUBLIC KEY-----';
  pem_c text := '-----BEGIN PUBLIC KEY-----' || E'\n' || encode(decode('302a300506032b6570032100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f','hex'),'base64') || E'\n-----END PUBLIC KEY-----';
  fp_a text := left(encode(extensions.digest(decode('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f','hex'),'sha256'),'hex'),16);
  fp_b text := left(encode(extensions.digest(decode('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f','hex'),'sha256'),'hex'),16);
  fp_c text := left(encode(extensions.digest(decode('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f','hex'),'sha256'),'hex'),16);
  org_a uuid;
  org_b uuid;
  project_a uuid;
  release_a uuid;
  release_b uuid;
  sbom_a uuid;
  component_a uuid;
  component_b uuid;
  key_a uuid;
  key_b uuid;
  n integer;
  approval_result jsonb;
begin
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  org_a := public.create_organization('FirmwareTrust Test Org','ft-test-org-rls-20261114');
  if not exists(select 1 from public.organization_memberships where organization_id=org_a and user_id=owner_id and role='owner') then
    raise exception 'FAIL: creator did not become first owner';
  end if;

  insert into public.projects(organization_id,name,slug,created_by)
  values(org_a,'FirmwareTrust Test Project','ft-test-project',owner_id)
  returning id into project_a;
  insert into public.releases(organization_id,project_id,version,artifact_name,artifact_sha256,manifest,status,created_by)
  values(org_a,project_a,'0.0.1','test-firmware.bin',repeat('a',64),jsonb_build_object('source','integration-test'),'draft',owner_id)
  returning id into release_a;

  begin
    insert into public.release_verification_attestations(organization_id,project_id,release_id,key_fingerprint,algorithm,manifest_sha256,signature_sha256,verifier_version)
    values(org_a,project_a,release_a,repeat('a',16),'Ed25519',repeat('b',64),repeat('c',64),'integration-test');
    raise exception 'FAIL: authenticated owner directly inserted a verification attestation';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.register_verified_release(org_a,project_a,'0.0.2','forged.bin',repeat('d',64),'{}'::jsonb,owner_id,repeat('a',16),repeat('b',64),repeat('c',64));
    raise exception 'FAIL: authenticated owner called the service-only verified registration RPC';
  exception when insufficient_privilege then null;
  end;

  if not exists(select 1 from public.audit_events where organization_id=org_a and action='release.registered' and resource_id=release_a::text) then
    raise exception 'FAIL: release registration was not audited';
  end if;

  sbom_a := public.ingest_sbom(
    org_a,project_a,release_a,'cyclonedx','1.6',repeat('b',64),
    jsonb_build_object('bomFormat','CycloneDX','specVersion','1.6','components',jsonb_build_array(
      jsonb_build_object('name','test-lib','version','1.2.3','purl','pkg:npm/test-lib@1.2.3'),
      jsonb_build_object('name','other-lib','version','2.3.4','purl','pkg:pypi/other-lib@2.3.4')
    )),
    jsonb_build_array(
      jsonb_build_object('component_name','test-lib','version','1.2.3','purl','pkg:npm/test-lib@1.2.3','license_expression','MIT','hashes',jsonb_build_object('SHA-256',repeat('a',64))),
      jsonb_build_object('component_name','other-lib','version','2.3.4','purl','pkg:pypi/other-lib@2.3.4','license_expression','Apache-2.0','hashes',jsonb_build_object('SHA-256',repeat('c',64)))
    )
  );
  select id into component_a from public.sbom_components where sbom_id=sbom_a and component_name='test-lib';
  select id into component_b from public.sbom_components where sbom_id=sbom_a and component_name='other-lib';
  if component_a is null or component_b is null then raise exception 'FAIL: SBOM component inventory was not persisted'; end if;
  if not exists(select 1 from public.audit_events where organization_id=org_a and action='sbom.ingested' and resource_id=sbom_a::text) then
    raise exception 'FAIL: SBOM ingestion was not audited';
  end if;
  if not exists(select 1 from public.sbom_documents where id=sbom_a and scan_status='pending' and scanned_component_count=0 and finding_count=0) then
    raise exception 'FAIL: initial SBOM scan state was not persisted';
  end if;

  insert into public.release_policies(organization_id,project_id,name,version,rules,enabled,created_by)
  values(org_a,project_a,'production-baseline',1,
    '{"require_signed_manifest":true,"require_sbom":true,"require_complete_sbom_scan":true,"block_on_critical":true,"max_high_findings":0,"min_approvals":1}'::jsonb,
    true,owner_id);
  if (public.evaluate_release_policy(release_a)->>'decision') <> 'block' then
    raise exception 'FAIL: policy evaluator did not block a release missing signature, completed scan and independent approval evidence';
  end if;

  perform public.request_release_approval(release_a);
  if not exists(select 1 from public.releases where id=release_a and status='pending_approval' and policy_id is not null) then
    raise exception 'FAIL: release review request did not pin a policy version';
  end if;

  insert into public.organization_memberships(organization_id,user_id,role)
  values(org_a,reviewer_user_id,'security_analyst');
  perform set_config('request.jwt.claim.sub',reviewer_user_id::text,true);
  perform public.submit_release_approval(release_a,'approved','Integration approval; policy evidence is intentionally incomplete');
  if not exists(select 1 from public.releases where id=release_a and status='pending_approval') then
    raise exception 'FAIL: incomplete policy evidence incorrectly advanced release to approved';
  end if;
  if not exists(select 1 from public.release_approvals a where a.release_id=release_a and a.reviewer_id=reviewer_user_id and a.decision='approved') then
    raise exception 'FAIL: reviewer decision was not persisted';
  end if;

  begin
    update public.releases set artifact_sha256=repeat('c',64) where id=release_a;
    raise exception 'FAIL: release artifact digest changed after review began';
  exception when raise_exception then
    if sqlerrm like 'FAIL:%' then raise; end if;
    if sqlerrm not like '%immutable after registration%' then raise; end if;
  end;
  if not exists(select 1 from public.audit_events where organization_id=org_a and action='release.approval.approved' and resource_id=release_a::text) then
    raise exception 'FAIL: reviewer decision was not appended to the audit chain';
  end if;

  begin
    perform public.submit_release_approval(release_a,'rejected','Duplicate reviewer decision must fail');
    raise exception 'FAIL: same reviewer submitted a second decision for the same policy version';
  exception when unique_violation then null;
  end;

  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  begin
    update public.releases set status='approved' where id=release_a;
    raise exception 'FAIL: direct release status update bypassed policy evaluation';
  exception when raise_exception then
    if sqlerrm like 'FAIL:%' then raise; end if;
    if sqlerrm not like '%Release cannot be approved%' then raise; end if;
  end;

  insert into public.signing_keys(organization_id,key_fingerprint,algorithm,public_key_pem,status,created_by)
  values(org_a,fp_a,'Ed25519',pem_a,'active',owner_id)
  returning id into key_a;

  insert into public.signing_keys(organization_id,project_id,key_fingerprint,algorithm,public_key_pem,status,created_by)
  values(org_a,project_a,fp_c,'Ed25519',pem_c,'active',owner_id);

  update public.sbom_documents
  set scan_status='complete',scanned_at=now(),scanned_component_count=2,finding_count=0,scan_warning=null
  where id=sbom_a;

  -- Exercise the trusted registration boundary with a disposable service-role fixture.
  set local role service_role;
  perform set_config('request.jwt.claim.role','service_role',true);
  perform public.register_verified_release(
    org_a,project_a,'0.0.2','verified-firmware.bin',repeat('e',64),
    jsonb_build_object(
      'trust_registry',jsonb_build_object('provider','firmwaretrust','organization_id',org_a::text,'project_id',project_a::text),
      'signature',jsonb_build_object('algorithm','Ed25519','key_id',fp_c,'value','c2lnbmF0dXJl'),
      'artifact',jsonb_build_object('filename','verified-firmware.bin','digest_algorithm','sha256','digest',repeat('e',64),'size_bytes',1)
    ),
    owner_id,fp_c,repeat('f',64),repeat('a',64)
  );
  set local role authenticated;
  perform set_config('request.jwt.claim.role','authenticated',true);
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  select id into release_b from public.releases where organization_id=org_a and version='0.0.2';
  if release_b is null or not exists(select 1 from public.release_verification_attestations where release_id=release_b) then
    raise exception 'FAIL: trusted registration did not atomically create a verification attestation';
  end if;
  update public.sbom_documents set release_id=release_b where id=sbom_a;
  perform public.request_release_approval(release_b);
  perform set_config('request.jwt.claim.sub',reviewer_user_id::text,true);
  approval_result := public.submit_release_approval(release_b,'approved','Independent approval for complete verified release evidence');
  if not exists(select 1 from public.releases where id=release_b and status='approved') then
    raise exception 'FAIL: complete verified release did not advance to approved; evaluation=%',approval_result::text;
  end if;
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform public.publish_release(release_b);
  if not exists(select 1 from public.releases where id=release_b and status='published' and published_at is not null) then
    raise exception 'FAIL: fully verified and approved release did not publish';
  end if;

  begin
    insert into public.signing_keys(organization_id,key_fingerprint,algorithm,public_key_pem,status,created_by)
    values(org_a,fp_a,'Ed25519',pem_b,'active',owner_id);
    raise exception 'FAIL: fingerprint mismatch was accepted';
  exception when raise_exception then
    if sqlerrm like 'FAIL:%' then raise; end if;
    if sqlerrm not like '%fingerprint does not match%' then raise; end if;
  end;

  begin
    insert into public.signing_keys(organization_id,key_fingerprint,algorithm,public_key_pem,status,created_by)
    values(org_a,fp_a,'Ed25519','-----BEGIN PRIVATE KEY-----' || E'\n' || repeat('A',80) || E'\n-----END PRIVATE KEY-----','active',owner_id);
    raise exception 'FAIL: private key PEM was accepted';
  exception when raise_exception then
    if sqlerrm like 'FAIL:%' then raise; end if;
    if sqlerrm not like '%private keys are never accepted%' then raise; end if;
  end;

  begin
    insert into public.signing_keys(organization_id,key_fingerprint,algorithm,public_key_pem,status,created_by)
    values(org_a,fp_a,'Ed25519',pem_a,'active',owner_id);
    raise exception 'FAIL: duplicate active fingerprint was accepted';
  exception when unique_violation then null;
  end;

  insert into public.organization_memberships(organization_id,user_id,role)
  values(org_a,developer_id,'developer');

  begin
    update public.signing_keys set public_key_pem=pem_b where id=key_a;
    raise exception 'FAIL: immutable public key material was changed';
  exception when raise_exception then
    if sqlerrm like 'FAIL:%' then raise; end if;
    if sqlerrm not like '%immutable%' then raise; end if;
  end;

  key_b := public.rotate_signing_key(org_a,key_a,fp_b,pem_b,'Ed25519');
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

  insert into public.vulnerability_findings(organization_id,sbom_id,component_id,advisory_id,source,severity,summary)
  values
    (org_a,sbom_a,component_a,'TEST-OSV-ADVISORY','OSV.dev','high','Synthetic integration finding for component A'),
    (org_a,sbom_a,component_b,'TEST-OSV-ADVISORY','OSV.dev','high','Synthetic integration finding for component B');
  if (select count(*) from public.vulnerability_findings where sbom_id=sbom_a and advisory_id='TEST-OSV-ADVISORY') <> 2 then
    raise exception 'FAIL: same advisory was not retained per affected component';
  end if;
  begin
    perform public.revoke_signing_key(org_a,key_a,'developer must not revoke keys');
    raise exception 'FAIL: developer role revoked a signing key';
  exception when raise_exception then
    if sqlerrm like 'FAIL:%' then raise; end if;
    if sqlerrm not like '%Not authorized%' then raise; end if;
  end;
  begin
    insert into public.signing_keys(organization_id,key_fingerprint,algorithm,public_key_pem,status,created_by)
    values(org_a,fp_c,'Ed25519',pem_c,'active',developer_id);
    raise exception 'FAIL: developer role registered a signing key';
  exception when insufficient_privilege then null;
  end;

  perform set_config('request.jwt.claim.sub',outsider_id::text,true);
  select count(*) into n from public.organizations where id=org_a;
  if n <> 0 then raise exception 'FAIL: cross-tenant organization read exposed % rows',n; end if;
  select count(*) into n from public.sbom_documents where id=sbom_a;
  if n <> 0 then raise exception 'FAIL: cross-tenant SBOM read exposed % rows',n; end if;
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

  invitation_result := public.create_organization_invitation(org_a,'ft-test-invitee@example.invalid','viewer',7);
  invite_token := invitation_result->>'token';
  invitation_id := (invitation_result->>'invitation_id')::uuid;
  if length(invite_token)<>64 or not exists(
    select 1 from public.organization_invitations i
    where i.id=invitation_id and i.token_hash=encode(extensions.digest(invite_token,'sha256'),'hex')
      and i.token_hash<>invite_token and i.email='ft-test-invitee@example.invalid' and i.role='viewer'
  ) then
    raise exception 'FAIL: invitation token was not securely hashed or role/email were not persisted';
  end if;
  if not exists(select 1 from public.audit_events where organization_id=org_a and action='organization.invitation.created' and resource_id=invitation_id::text) then
    raise exception 'FAIL: invitation creation was not audited';
  end if;
  begin
    perform public.create_organization_invitation(org_a,'ft-test-invitee@example.invalid','developer',7);
    raise exception 'FAIL: duplicate pending invitation was accepted';
  exception when unique_violation then null;
  end;

  perform set_config('request.jwt.claim.sub',reviewer_user_id::text,true);
  begin
    perform public.create_organization_invitation(org_a,'unauthorized@example.invalid','developer',7);
    raise exception 'FAIL: security analyst created an organization invitation';
  exception when insufficient_privilege then null;
  end;

  perform set_config('request.jwt.claim.sub',developer_id::text,true);
  perform set_config('request.jwt.claims',json_build_object('sub',developer_id::text,'email','ft-test-developer@example.invalid')::text,true);
  begin
    perform public.accept_organization_invitation(invite_token);
    raise exception 'FAIL: invitation was accepted by an account with the wrong email';
  exception when insufficient_privilege then null;
  end;

  perform set_config('request.jwt.claim.sub',invitee_id::text,true);
  perform set_config('request.jwt.claims',json_build_object('sub',invitee_id::text,'email','ft-test-invitee@example.invalid')::text,true);
  perform public.accept_organization_invitation(invite_token);
  if not exists(select 1 from public.organization_memberships where organization_id=org_a and user_id=invitee_id and role='viewer') then
    raise exception 'FAIL: invitation acceptance did not create the intended membership role';
  end if;
  if not exists(select 1 from public.organization_invitations where id=invitation_id and accepted_at is not null and accepted_by=invitee_id) then
    raise exception 'FAIL: invitation acceptance was not recorded';
  end if;
  if not exists(select 1 from public.audit_events where organization_id=org_a and action='organization.invitation.accepted' and resource_id=invitation_id::text) then
    raise exception 'FAIL: invitation acceptance was not audited';
  end if;
  begin
    perform public.accept_organization_invitation(invite_token);
    raise exception 'FAIL: invitation token was reused after acceptance';
  exception when unique_violation then null;
  end;

  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id::text,'email','ft-test-owner@example.invalid')::text,true);
  invitation_result := public.create_organization_invitation(org_a,'ft-test-revoked@example.invalid','developer',7);
  invitation_id := (invitation_result->>'invitation_id')::uuid;
  perform public.revoke_organization_invitation(invitation_id);
  if not exists(select 1 from public.organization_invitations where id=invitation_id and revoked_at is not null) then
    raise exception 'FAIL: invitation revocation was not persisted';
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
