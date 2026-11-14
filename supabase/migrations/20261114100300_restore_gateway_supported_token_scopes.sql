-- Match the issued-token scope set to the currently deployed API gateway routes.
alter table public.api_tokens drop constraint if exists api_tokens_current_scope_implemented;
alter table public.api_tokens add constraint api_tokens_current_scope_implemented
check (scopes <@ array['releases:write','releases:read','keys:read','audit:read']::text[]);
