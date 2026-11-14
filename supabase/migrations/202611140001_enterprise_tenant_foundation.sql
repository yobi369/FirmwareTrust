-- FirmwareTrust enterprise tenant foundation
-- Apply with Supabase migrations; never store firmware signing private keys here.

create extension if not exists pgcrypto;

create table if not exists public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(trim(name)) between 2 and 120),
  slug text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now()
);

create table if not exists public.organization_memberships (
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('owner','admin','release_manager','security_analyst','developer','viewer')),
  joined_at timestamptz not null default now(),
  primary key (organization_id,user_id)
);

create table if not exists public.projects (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null check (length(trim(name)) between 2 and 120),
  slug text not null,
  description text,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  unique (organization_id,slug),
  unique (organization_id,id)
);

create table if not exists public.releases (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  project_id uuid not null,
  version text not null,
  artifact_name text not null,
  artifact_sha256 text not null check (artifact_sha256 ~ '^[a-fA-F0-9]{64}$'),
  manifest jsonb not null default '{}'::jsonb,
  status text not null default 'draft' check (status in ('draft','pending_approval','approved','rejected','published','revoked')),
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  published_at timestamptz,
  unique (project_id,version),
  foreign key (organization_id,project_id) references public.projects(organization_id,id) on delete cascade
);

create table if not exists public.signing_keys (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  project_id uuid,
  key_fingerprint text not null,
  algorithm text not null default 'Ed25519',
  public_key_pem text not null,
  status text not null default 'active' check (status in ('active','rotated','revoked','expired')),
  valid_from timestamptz not null default now(),
  valid_until timestamptz,
  rotated_from uuid references public.signing_keys(id),
  revoked_at timestamptz,
  revoked_reason text,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  unique (organization_id,key_fingerprint),
  foreign key (organization_id,project_id) references public.projects(organization_id,id) on delete cascade
);

create table if not exists public.sbom_documents (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  project_id uuid not null,
  release_id uuid,
  format text not null check (format in ('cyclonedx','spdx')),
  spec_version text,
  document_sha256 text not null check (document_sha256 ~ '^[a-fA-F0-9]{64}$'),
  document jsonb not null,
  source text not null default 'upload',
  ingested_at timestamptz not null default now(),
  foreign key (organization_id,project_id) references public.projects(organization_id,id) on delete cascade,
  foreign key (release_id) references public.releases(id) on delete set null
);

create table if not exists public.sbom_components (
  id uuid primary key default gen_random_uuid(),
  sbom_id uuid not null references public.sbom_documents(id) on delete cascade,
  component_name text not null,
  version text,
  purl text,
  license_expression text,
  hashes jsonb not null default '{}'::jsonb
);

create table if not exists public.vulnerability_findings (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  sbom_id uuid not null references public.sbom_documents(id) on delete cascade,
  component_id uuid references public.sbom_components(id) on delete cascade,
  advisory_id text not null,
  source text not null,
  severity text check (severity in ('critical','high','medium','low','unknown')),
  summary text,
  affected_range text,
  fixed_version text,
  source_updated_at timestamptz,
  observed_at timestamptz not null default now(),
  unique (sbom_id,advisory_id,source)
);

create table if not exists public.release_policies (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  project_id uuid,
  name text not null,
  version integer not null check (version > 0),
  rules jsonb not null,
  enabled boolean not null default true,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  unique (organization_id,name,version),
  foreign key (organization_id,project_id) references public.projects(organization_id,id) on delete cascade
);

create table if not exists public.release_approvals (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  release_id uuid not null references public.releases(id) on delete cascade,
  policy_id uuid references public.release_policies(id) on delete set null,
  reviewer_id uuid not null references auth.users(id),
  decision text not null check (decision in ('approved','rejected','changes_requested')),
  comment text,
  decided_at timestamptz not null default now()
);

create table if not exists public.api_tokens (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  token_prefix text not null,
  token_hash text not null unique,
  scopes text[] not null default '{}',
  last_used_at timestamptz,
  expires_at timestamptz,
  revoked_at timestamptz,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now()
);

create table if not exists public.webhook_endpoints (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  url text not null check (url ~ '^https://'),
  event_types text[] not null,
  secret_hash text not null,
  active boolean not null default true,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now()
);

create table if not exists public.webhook_deliveries (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  endpoint_id uuid not null references public.webhook_endpoints(id) on delete cascade,
  event_id uuid not null,
  attempt integer not null default 1,
  response_status integer,
  delivered_at timestamptz,
  next_attempt_at timestamptz,
  created_at timestamptz not null default now(),
  unique (endpoint_id,event_id,attempt)
);

create table if not exists public.audit_events (
  id bigint generated always as identity primary key,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  actor_id uuid references auth.users(id) on delete set null,
  action text not null,
  resource_type text not null,
  resource_id text,
  metadata jsonb not null default '{}'::jsonb,
  previous_hash text,
  event_hash text not null,
  occurred_at timestamptz not null default now()
);

create or replace function public.is_org_member(target_org uuid)
returns boolean language sql stable security definer
set search_path = public
as $$
  select exists (
    select 1 from public.organization_memberships m
    where m.organization_id = target_org and m.user_id = auth.uid()
  );
$$;

create or replace function public.has_org_role(target_org uuid, allowed_roles text[])
returns boolean language sql stable security definer
set search_path = public
as $$
  select exists (
    select 1 from public.organization_memberships m
    where m.organization_id = target_org and m.user_id = auth.uid()
      and m.role = any(allowed_roles)
  );
$$;

create or replace function public.create_organization(org_name text, org_slug text)
returns uuid language plpgsql security definer
set search_path = public
as $$
declare new_org_id uuid;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  insert into public.organizations(name,slug,created_by)
  values (org_name,lower(org_slug),auth.uid()) returning id into new_org_id;
  insert into public.organization_memberships(organization_id,user_id,role)
  values (new_org_id,auth.uid(),'owner');
  return new_org_id;
end;
$$;

create or replace function public.prevent_audit_mutation()
returns trigger language plpgsql
as $$ begin raise exception 'Audit events are append-only'; end; $$;

drop trigger if exists audit_events_no_update on public.audit_events;
create trigger audit_events_no_update before update or delete on public.audit_events
for each row execute function public.prevent_audit_mutation();

alter table public.organizations enable row level security;
alter table public.organization_memberships enable row level security;
alter table public.projects enable row level security;
alter table public.releases enable row level security;
alter table public.signing_keys enable row level security;
alter table public.sbom_documents enable row level security;
alter table public.sbom_components enable row level security;
alter table public.vulnerability_findings enable row level security;
alter table public.release_policies enable row level security;
alter table public.release_approvals enable row level security;
alter table public.api_tokens enable row level security;
alter table public.webhook_endpoints enable row level security;
alter table public.webhook_deliveries enable row level security;
alter table public.audit_events enable row level security;

create policy "members read organizations" on public.organizations for select using (public.is_org_member(id));
create policy "members read memberships" on public.organization_memberships for select using (public.is_org_member(organization_id));
create policy "owners admins manage memberships" on public.organization_memberships for all using (public.has_org_role(organization_id,array['owner','admin'])) with check (public.has_org_role(organization_id,array['owner','admin']));
create policy "members read projects" on public.projects for select using (public.is_org_member(organization_id));
create policy "admins manage projects" on public.projects for all using (public.has_org_role(organization_id,array['owner','admin'])) with check (public.has_org_role(organization_id,array['owner','admin']));
create policy "members read releases" on public.releases for select using (public.is_org_member(organization_id));
create policy "release roles manage releases" on public.releases for all using (public.has_org_role(organization_id,array['owner','admin','release_manager','developer'])) with check (public.has_org_role(organization_id,array['owner','admin','release_manager','developer']));
create policy "members read signing keys" on public.signing_keys for select using (public.is_org_member(organization_id));
create policy "security roles manage signing keys" on public.signing_keys for all using (public.has_org_role(organization_id,array['owner','admin','security_analyst'])) with check (public.has_org_role(organization_id,array['owner','admin','security_analyst']));
create policy "members read sboms" on public.sbom_documents for select using (public.is_org_member(organization_id));
create policy "release roles manage sboms" on public.sbom_documents for all using (public.has_org_role(organization_id,array['owner','admin','release_manager','developer','security_analyst'])) with check (public.has_org_role(organization_id,array['owner','admin','release_manager','developer','security_analyst']));
create policy "members read components" on public.sbom_components for select using (exists(select 1 from public.sbom_documents s where s.id=sbom_id and public.is_org_member(s.organization_id)));
create policy "members read findings" on public.vulnerability_findings for select using (public.is_org_member(organization_id));
create policy "security roles manage findings" on public.vulnerability_findings for all using (public.has_org_role(organization_id,array['owner','admin','security_analyst'])) with check (public.has_org_role(organization_id,array['owner','admin','security_analyst']));
create policy "members read policies" on public.release_policies for select using (public.is_org_member(organization_id));
create policy "admins manage policies" on public.release_policies for all using (public.has_org_role(organization_id,array['owner','admin'])) with check (public.has_org_role(organization_id,array['owner','admin']));
create policy "members read approvals" on public.release_approvals for select using (public.is_org_member(organization_id));
create policy "reviewers create approvals" on public.release_approvals for insert with check (reviewer_id=auth.uid() and public.has_org_role(organization_id,array['owner','admin','release_manager','security_analyst']));
create policy "admins manage api tokens" on public.api_tokens for all using (public.has_org_role(organization_id,array['owner','admin'])) with check (public.has_org_role(organization_id,array['owner','admin']));
create policy "admins manage webhook endpoints" on public.webhook_endpoints for all using (public.has_org_role(organization_id,array['owner','admin'])) with check (public.has_org_role(organization_id,array['owner','admin']));
create policy "members read webhook deliveries" on public.webhook_deliveries for select using (public.is_org_member(organization_id));
create policy "members read audit events" on public.audit_events for select using (public.is_org_member(organization_id));
create policy "admins append audit events" on public.audit_events for insert with check (public.has_org_role(organization_id,array['owner','admin','release_manager','security_analyst','developer']));

revoke all on function public.create_organization(text,text) from public;
grant execute on function public.create_organization(text,text) to authenticated;
grant execute on function public.is_org_member(uuid) to authenticated;
grant execute on function public.has_org_role(uuid,text[]) to authenticated;
