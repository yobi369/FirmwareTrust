-- Expose only the API token scope backed by a live endpoint.
alter table public.api_tokens
  add constraint api_tokens_current_scope_implemented
  check (scopes <@ array['releases:write']::text[]);
