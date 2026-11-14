-- Pin policy versions and enforce independent, append-only release reviews.
alter table public.releases
  add column if not exists policy_id uuid references public.release_policies(id) on delete restrict;

create unique index if not exists release_approvals_one_decision_per_reviewer
  on public.release_approvals(release_id,policy_id,reviewer_id)
  where policy_id is not null;

create or replace function public.evaluate_release_policy(target_release uuid)
returns jsonb language plpgsql stable security invoker
set search_path = pg_catalog, public
as $$
declare
  rel public.releases%rowtype;
  policy public.release_policies%rowtype;
  has_policy boolean := false;
  signed_manifest boolean := false;
  sbom_count integer := 0;
  complete_sbom_count integer := 0;
  critical_count integer := 0;
  high_count integer := 0;
  approved_count integer := 0;
  min_approvals integer := 0;
  max_high integer;
  passed boolean := true;
  reasons jsonb := '[]'::jsonb;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode='28000'; end if;
  select * into rel from public.releases where id=target_release;
  if not found or not exists(select 1 from public.organization_memberships m where m.organization_id=rel.organization_id and m.user_id=auth.uid()) then
    raise exception 'Release not found or not accessible' using errcode='P0002';
  end if;

  if rel.policy_id is not null then
    select * into policy from public.release_policies p
    where p.id=rel.policy_id and p.organization_id=rel.organization_id
      and (p.project_id is null or p.project_id=rel.project_id);
  else
    select * into policy from public.release_policies p
    where p.organization_id=rel.organization_id and p.enabled
      and (p.project_id is null or p.project_id=rel.project_id)
    order by (p.project_id is not null) desc,p.version desc,p.created_at desc limit 1;
  end if;
  has_policy := found;
  if not has_policy then
    return jsonb_build_object('release_id',rel.id,'policy_applied',false,'decision','no_policy','passed',false,
      'reasons',jsonb_build_array('An enabled release policy is required before approval'));
  end if;

  if policy.rules - array['require_signed_manifest','require_sbom','require_complete_sbom_scan','block_on_critical','max_high_findings','min_approvals']::text[] <> '{}'::jsonb then
    raise exception 'Policy contains unsupported rule keys' using errcode='22023';
  end if;
  if (policy.rules ? 'max_high_findings' and (policy.rules->>'max_high_findings') !~ '^[0-9]{1,6}$')
     or (policy.rules ? 'min_approvals' and (policy.rules->>'min_approvals') !~ '^[0-9]{1,3}$') then
    raise exception 'Policy numeric rule values are invalid' using errcode='22023';
  end if;
  if exists(select 1 from jsonb_each(policy.rules) e where e.key in
    ('require_signed_manifest','require_sbom','require_complete_sbom_scan','block_on_critical') and jsonb_typeof(e.value)<>'boolean') then
    raise exception 'Policy boolean rule values are invalid' using errcode='22023';
  end if;

  signed_manifest := jsonb_typeof(rel.manifest->'signature')='object'
    and coalesce(length(rel.manifest->'signature'->>'value'),0)>0
    and jsonb_typeof(rel.manifest->'trust_registry')='object';
  min_approvals := coalesce((policy.rules->>'min_approvals')::integer,0);
  max_high := case when policy.rules ? 'max_high_findings' then (policy.rules->>'max_high_findings')::integer else null end;

  select count(*)::integer,count(*) filter(where d.scan_status='complete')::integer
  into sbom_count,complete_sbom_count
  from public.sbom_documents d where d.organization_id=rel.organization_id and d.project_id=rel.project_id
    and (d.release_id=rel.id or d.release_id is null);
  select count(*) filter(where lower(coalesce(f.severity,'unknown'))='critical')::integer,
         count(*) filter(where lower(coalesce(f.severity,'unknown'))='high')::integer
  into critical_count,high_count
  from public.vulnerability_findings f join public.sbom_documents d on d.id=f.sbom_id
  where d.organization_id=rel.organization_id and d.project_id=rel.project_id
    and (d.release_id=rel.id or d.release_id is null);
  select count(distinct a.reviewer_id)::integer into approved_count
  from public.release_approvals a where a.organization_id=rel.organization_id and a.release_id=rel.id
    and a.policy_id=policy.id and a.decision='approved' and a.reviewer_id<>rel.created_by;

  if coalesce((policy.rules->>'require_signed_manifest')::boolean,false) and not signed_manifest then
    passed:=false; reasons:=reasons||jsonb_build_array('A registry-scoped signed manifest is required; manifest field presence is not cryptographic verification');
  end if;
  if coalesce((policy.rules->>'require_sbom')::boolean,false) and sbom_count=0 then
    passed:=false; reasons:=reasons||jsonb_build_array('An SBOM is required');
  end if;
  if coalesce((policy.rules->>'require_complete_sbom_scan')::boolean,false) and (sbom_count=0 or complete_sbom_count<sbom_count) then
    passed:=false; reasons:=reasons||jsonb_build_array('All associated SBOM scans must be complete');
  end if;
  if coalesce((policy.rules->>'block_on_critical')::boolean,false) and critical_count>0 then
    passed:=false; reasons:=reasons||jsonb_build_array('Critical vulnerabilities block release');
  end if;
  if max_high is not null and high_count>max_high then
    passed:=false; reasons:=reasons||jsonb_build_array('High-severity vulnerability count exceeds the configured maximum');
  end if;
  if approved_count<min_approvals then
    passed:=false; reasons:=reasons||jsonb_build_array('Required independent approvals have not been collected');
  end if;

  return jsonb_build_object('release_id',rel.id,'policy_applied',true,'policy_id',policy.id,
    'policy_name',policy.name,'policy_version',policy.version,'decision',case when passed then 'pass' else 'block' end,
    'passed',passed,'reasons',reasons,'evidence',jsonb_build_object(
      'manifest_declares_signature_and_registry_scope',signed_manifest,'sbom_count',sbom_count,
      'complete_sbom_count',complete_sbom_count,'critical_findings',critical_count,
      'high_findings',high_count,'independent_approvals',approved_count),'evaluated_at',now());
end;
$$;

create or replace function public.guard_release_approval()
returns trigger language plpgsql security invoker
set search_path=pg_catalog,public
as $$
declare rel public.releases%rowtype; member_role text;
begin
  select * into rel from public.releases where id=new.release_id;
  if not found then raise exception 'Release not found or not accessible'; end if;
  if rel.organization_id is distinct from new.organization_id then raise exception 'Approval and release must belong to the same organization'; end if;
  if rel.created_by=new.reviewer_id then raise exception 'Release authors cannot approve their own releases'; end if;
  if auth.uid() is null or new.reviewer_id is distinct from auth.uid() then raise exception 'Approval reviewer must be the authenticated user'; end if;
  if rel.status<>'pending_approval' then raise exception 'Release must be pending approval before a decision can be submitted'; end if;
  if rel.policy_id is null or new.policy_id is distinct from rel.policy_id then raise exception 'Approval must reference the release policy version pinned at review request'; end if;
  select m.role into member_role from public.organization_memberships m where m.organization_id=rel.organization_id and m.user_id=auth.uid();
  if member_role is null or member_role not in ('owner','admin','release_manager','security_analyst') then raise exception 'Not authorized to review releases'; end if;
  return new;
end;
$$;

create or replace function public.prevent_release_approval_mutation()
returns trigger language plpgsql set search_path=pg_catalog,public
as $$ begin raise exception 'Release approval decisions are immutable; submit a new release review instead'; end; $$;
drop trigger if exists release_approvals_immutable on public.release_approvals;
create trigger release_approvals_immutable before update or delete on public.release_approvals
for each row execute function public.prevent_release_approval_mutation();

create or replace function public.prevent_release_policy_mutation()
returns trigger language plpgsql set search_path=pg_catalog,public
as $$ begin raise exception 'Release policy versions are immutable; create a new version instead'; end; $$;
drop trigger if exists release_policies_immutable on public.release_policies;
create trigger release_policies_immutable before update or delete on public.release_policies
for each row execute function public.prevent_release_policy_mutation();

create or replace function public.guard_release_state_transition()
returns trigger language plpgsql security invoker
set search_path=pg_catalog,public,private
as $$
declare evaluation jsonb;
begin
  if tg_op='INSERT' then
    if new.status<>'draft' then raise exception 'New releases must begin in draft status'; end if;
    return new;
  end if;
  if new.policy_id is distinct from old.policy_id and old.policy_id is not null then raise exception 'The policy version pinned to a release cannot be changed'; end if;
  if new.status is not distinct from old.status then return new; end if;
  if old.status='draft' and new.status='pending_approval' then
    if not private.has_org_role(new.organization_id,array['owner','admin','release_manager']) then raise exception 'Not authorized to request release approval'; end if;
    if new.policy_id is null or not exists(select 1 from public.release_policies p where p.id=new.policy_id and p.organization_id=new.organization_id and p.enabled and (p.project_id is null or p.project_id=new.project_id)) then
      raise exception 'An enabled matching policy version must be pinned before review';
    end if;
    return new;
  end if;
  if old.status='pending_approval' and new.status='approved' then
    if not exists(select 1 from public.release_approvals a where a.release_id=new.id and a.policy_id=new.policy_id and a.decision='approved' and a.reviewer_id<>new.created_by) then
      raise exception 'An independent approval decision is required';
    end if;
    evaluation:=public.evaluate_release_policy(new.id);
    if coalesce((evaluation->>'policy_applied')::boolean,false) is not true or coalesce((evaluation->>'passed')::boolean,false) is not true then
      raise exception 'Release cannot be approved: policy evaluation did not pass (%).',evaluation->>'reasons';
    end if;
    return new;
  end if;
  if old.status='pending_approval' and new.status='rejected' then
    if not exists(select 1 from public.release_approvals a where a.release_id=new.id and a.policy_id=new.policy_id and a.decision='rejected' and a.reviewer_id<>new.created_by) then
      raise exception 'A recorded independent rejection decision is required';
    end if;
    return new;
  end if;
  if old.status='approved' and new.status='published' then
    raise exception 'Publishing is disabled until non-forgeable cryptographic verification attestations are enforced';
  end if;
  raise exception 'Unsupported release status transition: % -> %',old.status,new.status;
end;
$$;
drop trigger if exists releases_guard_state on public.releases;
create trigger releases_guard_state before insert or update of status,policy_id on public.releases
for each row execute function public.guard_release_state_transition();

create or replace function private.audit_release_approval()
returns trigger language plpgsql security definer
set search_path=public,private
as $$
begin
  perform private.record_audit_event(new.organization_id,'release.approval.'||new.decision,'release',new.release_id::text,
    jsonb_build_object('approval_id',new.id,'policy_id',new.policy_id,'reviewer_id',new.reviewer_id,'comment',new.comment));
  return new;
end;
$$;
drop trigger if exists release_approvals_audit on public.release_approvals;
create trigger release_approvals_audit after insert on public.release_approvals
for each row execute function private.audit_release_approval();

create or replace function private.audit_release_status_transition()
returns trigger language plpgsql security definer
set search_path=public,private
as $$
begin
  if new.status is distinct from old.status then
    perform private.record_audit_event(new.organization_id,'release.status.'||new.status,'release',new.id::text,
      jsonb_build_object('from',old.status,'to',new.status,'policy_id',new.policy_id));
  end if;
  return new;
end;
$$;
drop trigger if exists releases_status_audit on public.releases;
create trigger releases_status_audit after update of status on public.releases
for each row execute function private.audit_release_status_transition();

create or replace function public.request_release_approval(target_release uuid)
returns jsonb language plpgsql security invoker
set search_path=pg_catalog,public,private
as $$
declare rel public.releases%rowtype; selected_policy uuid;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode='28000'; end if;
  select * into rel from public.releases where id=target_release for update;
  if not found then raise exception 'Release not found or not accessible' using errcode='P0002'; end if;
  if not private.has_org_role(rel.organization_id,array['owner','admin','release_manager']) then raise exception 'Not authorized to request release approval' using errcode='42501'; end if;
  if rel.status<>'draft' then raise exception 'Only draft releases can be submitted for review'; end if;
  select p.id into selected_policy from public.release_policies p
  where p.organization_id=rel.organization_id and p.enabled and (p.project_id is null or p.project_id=rel.project_id)
  order by (p.project_id is not null) desc,p.version desc,p.created_at desc limit 1;
  if selected_policy is null then raise exception 'An enabled release policy is required before review'; end if;
  update public.releases set policy_id=selected_policy,status='pending_approval' where id=rel.id;
  return jsonb_build_object('release_id',rel.id,'status','pending_approval','policy_id',selected_policy);
end;
$$;

create or replace function public.submit_release_approval(target_release uuid,approval_decision text,approval_comment text default null)
returns jsonb language plpgsql security invoker
set search_path=pg_catalog,public
as $$
declare rel public.releases%rowtype; approval_id uuid; evaluation jsonb; resulting_status text;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode='28000'; end if;
  if approval_decision not in ('approved','rejected') then raise exception 'Decision must be approved or rejected' using errcode='22023'; end if;
  if approval_comment is not null and length(approval_comment)>2000 then raise exception 'Approval comment exceeds 2000 characters' using errcode='22023'; end if;
  perform pg_advisory_xact_lock(hashtextextended(target_release::text,0));
  select * into rel from public.releases where id=target_release;
  if not found then raise exception 'Release not found or not accessible' using errcode='P0002'; end if;
  if rel.status<>'pending_approval' then raise exception 'Release is not awaiting approval'; end if;
  insert into public.release_approvals(organization_id,release_id,policy_id,reviewer_id,decision,comment)
  values(rel.organization_id,rel.id,rel.policy_id,auth.uid(),approval_decision,approval_comment) returning id into approval_id;
  if approval_decision='rejected' then
    update public.releases set status='rejected' where id=rel.id; resulting_status:='rejected';
  else
    evaluation:=public.evaluate_release_policy(rel.id);
    if coalesce((evaluation->>'passed')::boolean,false) then
      update public.releases set status='approved' where id=rel.id; resulting_status:='approved';
    else resulting_status:='pending_approval'; end if;
  end if;
  return jsonb_build_object('approval_id',approval_id,'release_id',rel.id,'status',resulting_status,'policy_evaluation',evaluation);
end;
$$;

revoke all on function public.evaluate_release_policy(uuid) from public,anon;
revoke all on function public.request_release_approval(uuid) from public,anon;
revoke all on function public.submit_release_approval(uuid,text,text) from public,anon;
grant execute on function public.evaluate_release_policy(uuid) to authenticated;
grant execute on function public.request_release_approval(uuid) to authenticated;
grant execute on function public.submit_release_approval(uuid,text,text) to authenticated;
revoke all on function public.guard_release_approval() from public,anon,authenticated;
revoke all on function public.prevent_release_approval_mutation() from public,anon,authenticated;
revoke all on function public.prevent_release_policy_mutation() from public,anon,authenticated;
revoke all on function public.guard_release_state_transition() from public,anon,authenticated;
revoke all on function private.audit_release_approval() from public,anon,authenticated;
revoke all on function private.audit_release_status_transition() from public,anon,authenticated;
