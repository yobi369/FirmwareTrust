-- Select the most recently authored applicable policy; version numbers are scoped to a policy name.
create or replace function public.evaluate_release_policy(target_release uuid)
returns jsonb language plpgsql stable security invoker
set search_path=pg_catalog,public
as $$
declare
  rel public.releases%rowtype; policy public.release_policies%rowtype; has_policy boolean:=false;
  signed_manifest boolean:=false; sbom_count integer:=0; complete_sbom_count integer:=0;
  critical_count integer:=0; high_count integer:=0; approved_count integer:=0;
  min_approvals integer:=0; max_high integer; passed boolean:=true; reasons jsonb:='[]'::jsonb;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode='28000'; end if;
  select * into rel from public.releases where id=target_release;
  if not found or not exists(select 1 from public.organization_memberships m where m.organization_id=rel.organization_id and m.user_id=auth.uid()) then
    raise exception 'Release not found or not accessible' using errcode='P0002';
  end if;
  if rel.policy_id is not null then
    select * into policy from public.release_policies p where p.id=rel.policy_id and p.organization_id=rel.organization_id
      and (p.project_id is null or p.project_id=rel.project_id);
  else
    select * into policy from public.release_policies p where p.organization_id=rel.organization_id and p.enabled
      and (p.project_id is null or p.project_id=rel.project_id)
    order by (p.project_id is not null) desc,p.created_at desc,p.version desc limit 1;
  end if;
  has_policy:=found;
  if not has_policy then return jsonb_build_object('release_id',rel.id,'policy_applied',false,'decision','no_policy','passed',false,
    'reasons',jsonb_build_array('An enabled release policy is required before approval')); end if;
  if policy.rules-array['require_signed_manifest','require_sbom','require_complete_sbom_scan','block_on_critical','max_high_findings','min_approvals']::text[]<>'{}'::jsonb then
    raise exception 'Policy contains unsupported rule keys' using errcode='22023'; end if;
  if (policy.rules?'max_high_findings' and (policy.rules->>'max_high_findings') !~ '^[0-9]{1,6}$')
    or (policy.rules?'min_approvals' and (policy.rules->>'min_approvals') !~ '^[0-9]{1,3}$') then
    raise exception 'Policy numeric rule values are invalid' using errcode='22023'; end if;
  if exists(select 1 from jsonb_each(policy.rules) e where e.key in ('require_signed_manifest','require_sbom','require_complete_sbom_scan','block_on_critical') and jsonb_typeof(e.value)<>'boolean') then
    raise exception 'Policy boolean rule values are invalid' using errcode='22023'; end if;
  signed_manifest:=jsonb_typeof(rel.manifest->'signature')='object' and coalesce(length(rel.manifest->'signature'->>'value'),0)>0 and jsonb_typeof(rel.manifest->'trust_registry')='object';
  min_approvals:=coalesce((policy.rules->>'min_approvals')::integer,0);
  max_high:=case when policy.rules?'max_high_findings' then (policy.rules->>'max_high_findings')::integer else null end;
  select count(*)::integer,count(*) filter(where d.scan_status='complete')::integer into sbom_count,complete_sbom_count
    from public.sbom_documents d where d.organization_id=rel.organization_id and d.project_id=rel.project_id and (d.release_id=rel.id or d.release_id is null);
  select count(*) filter(where lower(coalesce(f.severity,'unknown'))='critical')::integer,count(*) filter(where lower(coalesce(f.severity,'unknown'))='high')::integer into critical_count,high_count
    from public.vulnerability_findings f join public.sbom_documents d on d.id=f.sbom_id where d.organization_id=rel.organization_id and d.project_id=rel.project_id and (d.release_id=rel.id or d.release_id is null);
  select count(distinct a.reviewer_id)::integer into approved_count from public.release_approvals a where a.organization_id=rel.organization_id and a.release_id=rel.id and a.policy_id=policy.id and a.decision='approved' and a.reviewer_id<>rel.created_by;
  if coalesce((policy.rules->>'require_signed_manifest')::boolean,false) and not signed_manifest then passed:=false;reasons:=reasons||jsonb_build_array('A registry-scoped signed manifest is required; manifest field presence is not cryptographic verification');end if;
  if coalesce((policy.rules->>'require_sbom')::boolean,false) and sbom_count=0 then passed:=false;reasons:=reasons||jsonb_build_array('An SBOM is required');end if;
  if coalesce((policy.rules->>'require_complete_sbom_scan')::boolean,false) and (sbom_count=0 or complete_sbom_count<sbom_count) then passed:=false;reasons:=reasons||jsonb_build_array('All associated SBOM scans must be complete');end if;
  if coalesce((policy.rules->>'block_on_critical')::boolean,false) and critical_count>0 then passed:=false;reasons:=reasons||jsonb_build_array('Critical vulnerabilities block release');end if;
  if max_high is not null and high_count>max_high then passed:=false;reasons:=reasons||jsonb_build_array('High-severity vulnerability count exceeds the configured maximum');end if;
  if approved_count<min_approvals then passed:=false;reasons:=reasons||jsonb_build_array('Required independent approvals have not been collected');end if;
  return jsonb_build_object('release_id',rel.id,'policy_applied',true,'policy_id',policy.id,'policy_name',policy.name,'policy_version',policy.version,
    'decision',case when passed then 'pass' else 'block' end,'passed',passed,'reasons',reasons,
    'evidence',jsonb_build_object('manifest_declares_signature_and_registry_scope',signed_manifest,'sbom_count',sbom_count,
      'complete_sbom_count',complete_sbom_count,'critical_findings',critical_count,'high_findings',high_count,'independent_approvals',approved_count),'evaluated_at',now());
end;
$$;

create or replace function public.request_release_approval(target_release uuid)
returns jsonb language plpgsql security invoker set search_path=pg_catalog,public,private
as $$
declare rel public.releases%rowtype; selected_policy uuid;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode='28000'; end if;
  select * into rel from public.releases where id=target_release for update;
  if not found then raise exception 'Release not found or not accessible' using errcode='P0002'; end if;
  if not private.has_org_role(rel.organization_id,array['owner','admin','release_manager']) then raise exception 'Not authorized to request release approval' using errcode='42501'; end if;
  if rel.status<>'draft' then raise exception 'Only draft releases can be submitted for review'; end if;
  select p.id into selected_policy from public.release_policies p where p.organization_id=rel.organization_id and p.enabled
    and (p.project_id is null or p.project_id=rel.project_id)
    order by (p.project_id is not null) desc,p.created_at desc,p.version desc limit 1;
  if selected_policy is null then raise exception 'An enabled release policy is required before review'; end if;
  update public.releases set policy_id=selected_policy,status='pending_approval' where id=rel.id;
  return jsonb_build_object('release_id',rel.id,'status','pending_approval','policy_id',selected_policy);
end;
$$;
