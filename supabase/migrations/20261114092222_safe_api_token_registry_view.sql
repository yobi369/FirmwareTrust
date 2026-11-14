-- Expose only non-secret API-token metadata through a security-invoker view.
create or replace view public.api_token_registry
with (security_invoker=true)
as
select id,organization_id,name,token_prefix,scopes,project_ids,last_used_at,expires_at,revoked_at,created_by,created_at
from public.api_tokens;
revoke all on public.api_token_registry from public,anon;
grant select on public.api_token_registry to authenticated;
