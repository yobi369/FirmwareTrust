-- Correct helper references after privileged membership helpers were moved to private schema.
create or replace function public.guard_release_state_transition()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog, public, private
as $$
declare
  evaluation jsonb;
begin
  if tg_op = 'INSERT' then
    if new.status <> 'draft' then
      raise exception 'New releases must begin in draft status';
    end if;
    return new;
  end if;

  if new.policy_id is distinct from old.policy_id and old.policy_id is not null then
    raise exception 'The policy version pinned to a release cannot be changed';
  end if;
  if new.status is not distinct from old.status then return new; end if;

  if old.status = 'draft' and new.status = 'pending_approval' then
    if not private.has_org_role(new.organization_id,array['owner','admin','release_manager']) then
      raise exception 'Not authorized to request release approval';
    end if;
    if new.policy_id is null or not exists (
      select 1 from public.release_policies p
      where p.id = new.policy_id and p.organization_id = new.organization_id
        and p.enabled and (p.project_id is null or p.project_id = new.project_id)
    ) then
      raise exception 'An enabled matching policy version must be pinned before review';
    end if;
    return new;
  end if;

  if old.status = 'pending_approval' and new.status = 'approved' then
    evaluation := public.evaluate_release_policy(new.id);
    if coalesce((evaluation->>'policy_applied')::boolean,false) is not true
       or coalesce((evaluation->>'passed')::boolean,false) is not true then
      raise exception 'Release cannot be approved: policy evaluation did not pass (%).', evaluation->>'reasons';
    end if;
    return new;
  end if;

  if old.status = 'pending_approval' and new.status = 'rejected' then
    if not exists (
      select 1 from public.release_approvals a
      where a.release_id = new.id and a.policy_id = new.policy_id
        and a.decision = 'rejected' and a.reviewer_id <> new.created_by
    ) then
      raise exception 'A recorded independent rejection decision is required';
    end if;
    return new;
  end if;

  if old.status = 'approved' and new.status = 'published' then
    raise exception 'Publishing is disabled until non-forgeable cryptographic verification attestations are enforced';
  end if;
  raise exception 'Unsupported release status transition: % -> %',old.status,new.status;
end;
$$;

create or replace function public.request_release_approval(target_release uuid)
returns jsonb
language plpgsql
security invoker
set search_path = pg_catalog, public, private
as $$
declare
  rel public.releases%rowtype;
  selected_policy uuid;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '28000'; end if;
  select * into rel from public.releases where id = target_release for update;
  if not found then raise exception 'Release not found or not accessible' using errcode = 'P0002'; end if;
  if not private.has_org_role(rel.organization_id,array['owner','admin','release_manager']) then
    raise exception 'Not authorized to request release approval' using errcode = '42501';
  end if;
  if rel.status <> 'draft' then raise exception 'Only draft releases can be submitted for review'; end if;
  select p.id into selected_policy
  from public.release_policies p
  where p.organization_id = rel.organization_id and p.enabled
    and (p.project_id is null or p.project_id = rel.project_id)
  order by (p.project_id is not null) desc,p.version desc,p.created_at desc
  limit 1;
  if selected_policy is null then raise exception 'An enabled release policy is required before review'; end if;
  update public.releases set policy_id = selected_policy,status = 'pending_approval' where id = rel.id;
  return jsonb_build_object('release_id',rel.id,'status','pending_approval','policy_id',selected_policy);
end;
$$;
