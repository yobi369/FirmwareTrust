-- Non-forgeable release verification attestations and gated publication.
create table public.release_verification_attestations (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  project_id uuid not null,
  release_id uuid not null unique references public.releases(id) on delete cascade,
  key_fingerprint text not null check (key_fingerprint ~ '^[a-f0-9]{16}$'),
  algorithm text not null check (algorithm='Ed25519'),
  manifest_sha256 text not null check (manifest_sha256 ~ '^[a-f0-9]{64}$'),
  signature_sha256 text not null check (signature_sha256 ~ '^[a-f0-9]{64}$'),
  verifier_version text not null check (length(verifier_version) between 1 and 80),
  verified_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  foreign key (organization_id,project_id) references public.projects(organization_id,id) on delete cascade
);
create index idx_release_attestations_org_project on public.release_verification_attestations(organization_id,project_id,verified_at desc);
alter table public.release_verification_attestations enable row level security;
create policy "members read release attestations" on public.release_verification_attestations for select using (private.is_org_member(organization_id));
grant select on public.release_verification_attestations to authenticated;
revoke all on public.release_verification_attestations from anon,authenticated;

create or replace function private.record_system_audit_event(target_org uuid,target_actor uuid,event_action text,event_resource_type text,event_resource_id text default null,event_metadata jsonb default '{}'::jsonb)
returns bigint language plpgsql security definer set search_path=public,extensions,private
as $$
declare prev text; next_hash text; new_id bigint; occurred timestamptz:=clock_timestamp();
begin
  if target_actor is null or not exists(select 1 from public.organization_memberships m where m.organization_id=target_org and m.user_id=target_actor) then
    raise exception 'Audit actor must be a member of the target organization'; end if;
  perform pg_advisory_xact_lock(hashtext(target_org::text));
  select event_hash into prev from public.audit_events where organization_id=target_org order by id desc limit 1;
  next_hash:=encode(extensions.digest(coalesce(prev,'')||'|'||target_org::text||'|'||target_actor::text||'|'||event_action||'|'||
    event_resource_type||'|'||coalesce(event_resource_id,'')||'|'||coalesce(event_metadata,'{}'::jsonb)::text||'|'||occurred::text,'sha256'),'hex');
  insert into public.audit_events(organization_id,actor_id,action,resource_type,resource_id,metadata,previous_hash,event_hash,occurred_at)
  values(target_org,target_actor,event_action,event_resource_type,event_resource_id,coalesce(event_metadata,'{}'::jsonb),prev,next_hash,occurred)
  returning id into new_id;
  return new_id;
end;
$$;

create or replace function private.guard_release_verification_attestation()
returns trigger language plpgsql security definer set search_path=public,private
as $$
declare rel public.releases%rowtype; key_row public.signing_keys%rowtype;
begin
  if auth.role() is distinct from 'service_role' then raise exception 'Only the verified release-registration service can create attestations'; end if;
  select * into rel from public.releases where id=new.release_id;
  if not found then raise exception 'Attested release does not exist'; end if;
  if rel.organization_id is distinct from new.organization_id or rel.project_id is distinct from new.project_id then raise exception 'Attestation tenant scope does not match its release'; end if;
  if rel.status<>'draft' then raise exception 'Only a newly registered draft can receive its verification attestation'; end if;
  if rel.manifest->'trust_registry'->>'provider'<>'firmwaretrust'
    or rel.manifest->'trust_registry'->>'organization_id'<>rel.organization_id::text
    or rel.manifest->'trust_registry'->>'project_id'<>rel.project_id::text
    or rel.manifest->'signature'->>'algorithm'<>'Ed25519'
    or lower(rel.manifest->'signature'->>'key_id')<>new.key_fingerprint then
    raise exception 'Attestation does not match the signed manifest trust scope'; end if;
  if rel.manifest->'artifact'->>'filename'<>rel.artifact_name
    or rel.manifest->'artifact'->>'digest_algorithm'<>'sha256'
    or lower(rel.manifest->'artifact'->>'digest')<>lower(rel.artifact_sha256) then
    raise exception 'Attested artifact metadata does not match the release record'; end if;
  select * into key_row from public.signing_keys k where k.organization_id=rel.organization_id and k.project_id=rel.project_id
    and k.key_fingerprint=new.key_fingerprint and k.algorithm='Ed25519' and k.status='active'
    and k.valid_from<=new.verified_at and (k.valid_until is null or k.valid_until>new.verified_at);
  if not found then raise exception 'Signing key was not active at attestation time'; end if;
  return new;
end;
$$;
create trigger release_attestation_guard before insert on public.release_verification_attestations for each row execute function private.guard_release_verification_attestation();

create or replace function private.prevent_release_attestation_mutation()
returns trigger language plpgsql set search_path=pg_catalog,public
as $$ begin raise exception 'Release verification attestations are immutable'; end; $$;
create trigger release_attestations_immutable before update or delete on public.release_verification_attestations for each row execute function private.prevent_release_attestation_mutation();

create or replace function private.audit_release_verification_attestation()
returns trigger language plpgsql security definer set search_path=public,private
as $$
declare actor uuid;
begin
  select created_by into actor from public.releases where id=new.release_id;
  perform private.record_system_audit_event(new.organization_id,actor,'release.signature.verified','release',new.release_id::text,
    jsonb_build_object('attestation_id',new.id,'key_fingerprint',new.key_fingerprint,'algorithm',new.algorithm,
      'manifest_sha256',new.manifest_sha256,'signature_sha256',new.signature_sha256,'verifier_version',new.verifier_version));
  return new;
end;
$$;
create trigger release_attestation_audit after insert on public.release_verification_attestations for each row execute function private.audit_release_verification_attestation();

create or replace function private.audit_release_registration()
returns trigger language plpgsql security definer set search_path=public,private
as $$
begin
  if auth.role() is distinct from 'service_role' and (auth.uid() is null or new.created_by is distinct from auth.uid()) then
    raise exception 'Release creator must be the authenticated user or trusted registration service'; end if;
  perform private.record_system_audit_event(new.organization_id,new.created_by,'release.registered','release',new.id::text,
    jsonb_build_object('project_id',new.project_id,'version',new.version,'artifact_name',new.artifact_name,'artifact_sha256',new.artifact_sha256,'status',new.status));
  return new;
end;
$$;

create or replace function private.register_verified_release(target_org uuid,target_project uuid,target_version text,target_artifact_name text,
  target_artifact_sha256 text,target_manifest jsonb,target_actor uuid,target_key_fingerprint text,target_manifest_sha256 text,target_signature_sha256 text)
returns jsonb language plpgsql security definer set search_path=pg_catalog,public,private
as $$
declare new_release_id uuid;
begin
  if auth.role() is distinct from 'service_role' then raise exception 'Trusted registration service required' using errcode='42501'; end if;
  if not exists(select 1 from public.organization_memberships m where m.organization_id=target_org and m.user_id=target_actor and m.role in ('owner','admin','release_manager','developer')) then
    raise exception 'Actor is not authorized to register releases in this organization' using errcode='42501'; end if;
  if not exists(select 1 from public.projects p where p.organization_id=target_org and p.id=target_project) then raise exception 'Project is not part of the target organization'; end if;
  insert into public.releases(organization_id,project_id,version,artifact_name,artifact_sha256,manifest,status,created_by)
  values(target_org,target_project,target_version,target_artifact_name,lower(target_artifact_sha256),target_manifest,'draft',target_actor)
  returning id into new_release_id;
  insert into public.release_verification_attestations(organization_id,project_id,release_id,key_fingerprint,algorithm,manifest_sha256,signature_sha256,verifier_version)
  values(target_org,target_project,new_release_id,lower(target_key_fingerprint),'Ed25519',lower(target_manifest_sha256),lower(target_signature_sha256),'register-release/v2');
  return jsonb_build_object('release_id',new_release_id,'signature_verified',true,'attestation_created',true);
end;
$$;

create or replace function public.register_verified_release(target_org uuid,target_project uuid,target_version text,target_artifact_name text,
  target_artifact_sha256 text,target_manifest jsonb,target_actor uuid,target_key_fingerprint text,target_manifest_sha256 text,target_signature_sha256 text)
returns jsonb language sql security invoker set search_path=pg_catalog,public,private
as $$ select private.register_verified_release(target_org,target_project,target_version,target_artifact_name,target_artifact_sha256,target_manifest,target_actor,target_key_fingerprint,target_manifest_sha256,target_signature_sha256); $$;

create or replace function public.evaluate_release_policy(target_release uuid)
returns jsonb language plpgsql stable security invoker set search_path=pg_catalog,public
as $$
declare rel public.releases%rowtype; policy public.release_policies%rowtype; has_policy boolean:=false; signed_manifest boolean:=false;
  sbom_count integer:=0; complete_sbom_count integer:=0; critical_count integer:=0; high_count integer:=0; approved_count integer:=0;
  min_approvals integer:=0; max_high integer; passed boolean:=true; reasons jsonb:='[]'::jsonb;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode='28000'; end if;
  select * into rel from public.releases where id=target_release;
  if not found or not exists(select 1 from public.organization_memberships m where m.organization_id=rel.organization_id and m.user_id=auth.uid()) then raise exception 'Release not found or not accessible' using errcode='P0002'; end if;
  if rel.policy_id is not null then select * into policy from public.release_policies p where p.id=rel.policy_id and p.organization_id=rel.organization_id and (p.project_id is null or p.project_id=rel.project_id);
  else select * into policy from public.release_policies p where p.organization_id=rel.organization_id and p.enabled and (p.project_id is null or p.project_id=rel.project_id) order by (p.project_id is not null) desc,p.created_at desc,p.version desc limit 1; end if;
  has_policy:=found;
  if not has_policy then return jsonb_build_object('release_id',rel.id,'policy_applied',false,'decision','no_policy','passed',false,'reasons',jsonb_build_array('An enabled release policy is required before approval')); end if;
  if policy.rules-array['require_signed_manifest','require_sbom','require_complete_sbom_scan','block_on_critical','max_high_findings','min_approvals']::text[]<>'{}'::jsonb then raise exception 'Policy contains unsupported rule keys' using errcode='22023'; end if;
  if (policy.rules?'max_high_findings' and (policy.rules->>'max_high_findings') !~ '^[0-9]{1,6}$') or (policy.rules?'min_approvals' and (policy.rules->>'min_approvals') !~ '^[0-9]{1,3}$') then raise exception 'Policy numeric rule values are invalid' using errcode='22023'; end if;
  if exists(select 1 from jsonb_each(policy.rules) e where e.key in ('require_signed_manifest','require_sbom','require_complete_sbom_scan','block_on_critical') and jsonb_typeof(e.value)<>'boolean') then raise exception 'Policy boolean rule values are invalid' using errcode='22023'; end if;
  select exists(select 1 from public.release_verification_attestations a where a.release_id=rel.id and a.organization_id=rel.organization_id and a.project_id=rel.project_id and a.key_fingerprint=lower(rel.manifest->'signature'->>'key_id') and a.algorithm='Ed25519') into signed_manifest;
  min_approvals:=coalesce((policy.rules->>'min_approvals')::integer,0); max_high:=case when policy.rules?'max_high_findings' then (policy.rules->>'max_high_findings')::integer else null end;
  select count(*)::integer,count(*) filter(where d.scan_status='complete')::integer into sbom_count,complete_sbom_count from public.sbom_documents d where d.organization_id=rel.organization_id and d.project_id=rel.project_id and (d.release_id=rel.id or d.release_id is null);
  select count(*) filter(where lower(coalesce(f.severity,'unknown'))='critical')::integer,count(*) filter(where lower(coalesce(f.severity,'unknown'))='high')::integer into critical_count,high_count from public.vulnerability_findings f join public.sbom_documents d on d.id=f.sbom_id where d.organization_id=rel.organization_id and d.project_id=rel.project_id and (d.release_id=rel.id or d.release_id is null);
  select count(distinct a.reviewer_id)::integer into approved_count from public.release_approvals a where a.organization_id=rel.organization_id and a.release_id=rel.id and a.policy_id=policy.id and a.decision='approved' and a.reviewer_id<>rel.created_by;
  if coalesce((policy.rules->>'require_signed_manifest')::boolean,false) and not signed_manifest then passed:=false;reasons:=reasons||jsonb_build_array('A non-forgeable server-side signature verification attestation is required'); end if;
  if coalesce((policy.rules->>'require_sbom')::boolean,false) and sbom_count=0 then passed:=false;reasons:=reasons||jsonb_build_array('An SBOM is required'); end if;
  if coalesce((policy.rules->>'require_complete_sbom_scan')::boolean,false) and (sbom_count=0 or complete_sbom_count<sbom_count) then passed:=false;reasons:=reasons||jsonb_build_array('All associated SBOM scans must be complete'); end if;
  if coalesce((policy.rules->>'block_on_critical')::boolean,false) and critical_count>0 then passed:=false;reasons:=reasons||jsonb_build_array('Critical vulnerabilities block release'); end if;
  if max_high is not null and high_count>max_high then passed:=false;reasons:=reasons||jsonb_build_array('High-severity vulnerability count exceeds the configured maximum'); end if;
  if approved_count<min_approvals then passed:=false;reasons:=reasons||jsonb_build_array('Required independent approvals have not been collected'); end if;
  return jsonb_build_object('release_id',rel.id,'policy_applied',true,'policy_id',policy.id,'policy_name',policy.name,'policy_version',policy.version,'decision',case when passed then 'pass' else 'block' end,'passed',passed,'reasons',reasons,'evidence',jsonb_build_object('non_forgeable_signature_attestation',signed_manifest,'sbom_count',sbom_count,'complete_sbom_count',complete_sbom_count,'critical_findings',critical_count,'high_findings',high_count,'independent_approvals',approved_count),'evaluated_at',now());
end;
$$;

create or replace function public.guard_release_state_transition()
returns trigger language plpgsql security invoker set search_path=pg_catalog,public,private
as $$
declare evaluation jsonb; analyst_only boolean;
begin
  if tg_op='INSERT' then if new.status<>'draft' then raise exception 'New releases must begin in draft status'; end if; if new.published_at is not null then raise exception 'A draft release cannot have a publication timestamp'; end if; return new; end if;
  if (to_jsonb(new)-'status'-'policy_id'-'published_at') is distinct from (to_jsonb(old)-'status'-'policy_id'-'published_at') then raise exception 'Release identity, artifact digest and manifest are immutable after registration'; end if;
  if new.policy_id is distinct from old.policy_id and old.policy_id is not null then raise exception 'The policy version pinned to a release cannot be changed'; end if;
  if new.status<>'published' and new.published_at is not null then raise exception 'Publication timestamp can only be set by the verified publication workflow'; end if;
  if new.status is not distinct from old.status then return new; end if;
  analyst_only:=private.has_org_role(new.organization_id,array['security_analyst']) and not private.has_org_role(new.organization_id,array['owner','admin','release_manager','developer']);
  if analyst_only and (to_jsonb(new)-'status'-'published_at') is distinct from (to_jsonb(old)-'status'-'published_at') then raise exception 'Security analysts may change review state only; release metadata is immutable to reviewers'; end if;
  if old.status='draft' and new.status='pending_approval' then
    if not private.has_org_role(new.organization_id,array['owner','admin','release_manager']) then raise exception 'Not authorized to request release approval'; end if;
    if new.policy_id is null or not exists(select 1 from public.release_policies p where p.id=new.policy_id and p.organization_id=new.organization_id and p.enabled and (p.project_id is null or p.project_id=new.project_id)) then raise exception 'An enabled matching policy version must be pinned before review'; end if; return new;
  end if;
  if old.status='pending_approval' and new.status='approved' then
    if not exists(select 1 from public.release_approvals a where a.release_id=new.id and a.policy_id=new.policy_id and a.decision='approved' and a.reviewer_id<>new.created_by) then raise exception 'An independent approval decision is required'; end if;
    evaluation:=public.evaluate_release_policy(new.id); if coalesce((evaluation->>'policy_applied')::boolean,false) is not true or coalesce((evaluation->>'passed')::boolean,false) is not true then raise exception 'Release cannot be approved: policy evaluation did not pass (%).',evaluation->>'reasons'; end if; return new;
  end if;
  if old.status='pending_approval' and new.status='rejected' then
    if not exists(select 1 from public.release_approvals a where a.release_id=new.id and a.policy_id=new.policy_id and a.decision='rejected' and a.reviewer_id<>new.created_by) then raise exception 'A recorded independent rejection decision is required'; end if; return new;
  end if;
  if old.status='approved' and new.status='published' then
    if not private.has_org_role(new.organization_id,array['owner','admin','release_manager']) then raise exception 'Not authorized to publish releases'; end if;
    if not exists(select 1 from public.release_verification_attestations a where a.release_id=new.id and a.organization_id=new.organization_id and a.project_id=new.project_id) then raise exception 'A non-forgeable cryptographic verification attestation is required before publication'; end if;
    evaluation:=public.evaluate_release_policy(new.id); if coalesce((evaluation->>'passed')::boolean,false) is not true then raise exception 'Release cannot be published: policy evaluation did not pass (%).',evaluation->>'reasons'; end if;
    new.published_at:=clock_timestamp(); return new;
  end if;
  raise exception 'Unsupported release status transition: % -> %',old.status,new.status;
end;
$$;

create or replace function public.publish_release(target_release uuid)
returns jsonb language plpgsql security invoker set search_path=pg_catalog,public,private
as $$
declare rel public.releases%rowtype; evaluation jsonb;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode='28000'; end if;
  select * into rel from public.releases where id=target_release for update;
  if not found then raise exception 'Release not found or not accessible' using errcode='P0002'; end if;
  if not private.has_org_role(rel.organization_id,array['owner','admin','release_manager']) then raise exception 'Not authorized to publish releases' using errcode='42501'; end if;
  if rel.status<>'approved' then raise exception 'Only an approved release can be published'; end if;
  if not exists(select 1 from public.release_verification_attestations a where a.release_id=rel.id and a.organization_id=rel.organization_id and a.project_id=rel.project_id) then raise exception 'A non-forgeable cryptographic verification attestation is required before publication'; end if;
  evaluation:=public.evaluate_release_policy(rel.id); if coalesce((evaluation->>'passed')::boolean,false) is not true then raise exception 'Release cannot be published until policy evaluation passes'; end if;
  update public.releases set status='published',published_at=now() where id=rel.id;
  return jsonb_build_object('release_id',rel.id,'status','published','published_at',now(),'policy_evaluation',evaluation);
end;
$$;

revoke all on function public.register_verified_release(uuid,uuid,text,text,text,jsonb,uuid,text,text,text) from public,anon,authenticated;
grant usage on schema private to service_role;
grant execute on function private.register_verified_release(uuid,uuid,text,text,text,jsonb,uuid,text,text,text) to service_role;
grant execute on function public.register_verified_release(uuid,uuid,text,text,text,jsonb,uuid,text,text,text) to service_role;
revoke all on function public.publish_release(uuid) from public,anon;
grant execute on function public.publish_release(uuid) to authenticated;
revoke all on function private.record_system_audit_event(uuid,uuid,text,text,text,jsonb) from public,anon,authenticated,service_role;
revoke all on function private.guard_release_verification_attestation() from public,anon,authenticated,service_role;
revoke all on function private.prevent_release_attestation_mutation() from public,anon,authenticated,service_role;
revoke all on function private.audit_release_verification_attestation() from public,anon,authenticated,service_role;
revoke all on function private.register_verified_release(uuid,uuid,text,text,text,jsonb,uuid,text,text,text) from public,anon,authenticated;
