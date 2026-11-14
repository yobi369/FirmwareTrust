-- Security analysts can review without receiving release UPDATE privileges.
create or replace function public.guard_release_approval()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog, public
as $$
declare
  rel public.releases%rowtype;
  member_role text;
begin
  select * into rel from public.releases where id = new.release_id;
  if not found then raise exception 'Release not found or not accessible'; end if;
  if rel.organization_id is distinct from new.organization_id then
    raise exception 'Approval and release must belong to the same organization';
  end if;
  if rel.created_by = new.reviewer_id then raise exception 'Release authors cannot approve their own releases'; end if;
  if auth.uid() is null or new.reviewer_id is distinct from auth.uid() then
    raise exception 'Approval reviewer must be the authenticated user';
  end if;
  if rel.status <> 'pending_approval' then raise exception 'Release must be pending approval before a decision can be submitted'; end if;
  if rel.policy_id is null or new.policy_id is distinct from rel.policy_id then
    raise exception 'Approval must reference the release policy version pinned at review request';
  end if;
  select m.role into member_role
  from public.organization_memberships m
  where m.organization_id = rel.organization_id and m.user_id = auth.uid();
  if member_role is null or member_role not in ('owner','admin','release_manager','security_analyst') then
    raise exception 'Not authorized to review releases';
  end if;
  return new;
end;
$$;

create or replace function public.submit_release_approval(
  target_release uuid,
  approval_decision text,
  approval_comment text default null
)
returns jsonb
language plpgsql
security invoker
set search_path = pg_catalog, public
as $$
declare
  rel public.releases%rowtype;
  approval_id uuid;
  evaluation jsonb;
  resulting_status text;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '28000'; end if;
  if approval_decision not in ('approved','rejected') then
    raise exception 'Decision must be approved or rejected' using errcode = '22023';
  end if;
  if approval_comment is not null and length(approval_comment) > 2000 then
    raise exception 'Approval comment exceeds 2000 characters' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(target_release::text,0));
  select * into rel from public.releases where id = target_release;
  if not found then raise exception 'Release not found or not accessible' using errcode = 'P0002'; end if;
  if rel.status <> 'pending_approval' then raise exception 'Release is not awaiting approval'; end if;

  insert into public.release_approvals(organization_id,release_id,policy_id,reviewer_id,decision,comment)
  values(rel.organization_id,rel.id,rel.policy_id,auth.uid(),approval_decision,approval_comment)
  returning id into approval_id;

  if approval_decision = 'rejected' then
    update public.releases set status = 'rejected' where id = rel.id;
    resulting_status := 'rejected';
  else
    evaluation := public.evaluate_release_policy(rel.id);
    if coalesce((evaluation->>'passed')::boolean,false) then
      update public.releases set status = 'approved' where id = rel.id;
      resulting_status := 'approved';
    else
      resulting_status := 'pending_approval';
    end if;
  end if;

  return jsonb_build_object('approval_id',approval_id,'release_id',rel.id,'status',resulting_status,'policy_evaluation',evaluation);
end;
$$;
