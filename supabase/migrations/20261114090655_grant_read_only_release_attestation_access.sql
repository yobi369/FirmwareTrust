-- Authenticated tenant members may inspect attestations but cannot create or mutate them.
grant select on public.release_verification_attestations to authenticated;
revoke insert,update,delete,truncate,references,trigger on public.release_verification_attestations from anon,authenticated;
