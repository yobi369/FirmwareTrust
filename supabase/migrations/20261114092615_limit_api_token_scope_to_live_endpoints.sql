-- Restrict token scopes to API surfaces that are currently live at this milestone.
alter table public.api_tokens
 add constraint api_tokens_current_scope_implemented_check
 check (scopes <@ array['releases:read','releases:write','keys:read','audit:read']::text[]);
