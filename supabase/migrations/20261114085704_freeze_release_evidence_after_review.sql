-- Freeze release identity and signed evidence as soon as review begins.
create or replace function public.guard_release_state_transition()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog, public, private
as $$
declare
  evaluation jsonb;
  analyst_only boolean;
begin
  if tg_op='INSERT' then
    if new.status<>'draft' then raise exception 'New releases must begin in draft status'; end if;
    return new;
  end if;

  if new.policy_id is distinct from old.policy_id and old.policy_id is not null then
    raise exception 'The policy version pinned to a release cannot be changed';
  end if;
  if old.status<>'draft' or new.status is distinct from old.status then
    if (to_jsonb(new) - 'status' - 'policy_id' - 'published_at')
       is distinct from (to_jsonb(old) - 'status' - 'policy_id' - 'published_at') then
      raise exception 'Release identity, artifact digest and manifest are immutable once review begins';
    end if;
  end if;
  if new.status is not distinct from old.status then return new; end if;

  analyst_only := private.has_org_role(new.organization_id,array['security_analyst'])
    and not private.has_org_role(new.organization_id,array['owner','admin','release_manager','developer']);
  if analyst_only and
     (to_jsonb(new) - 'status' - 'published_at') is distinct from (to_jsonb(old) - 'status' - 'published_at') then
    raise exception 'Security analysts may change review state only; release metadata is immutable to reviewers';
  end if;

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
