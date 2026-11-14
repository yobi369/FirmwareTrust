grant select (id,organization_id,name,token_prefix,scopes,project_ids,last_used_at,expires_at,revoked_at,created_by,created_at)
on public.api_tokens to authenticated;
