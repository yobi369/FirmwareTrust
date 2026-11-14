import { assertEquals } from "jsr:@std/assert@1";
import { apiTokenAllows, hashApiToken, type ApiTokenRecord } from "./api_tokens.ts";

const secret = "ft_live_0123456789abcdefghijklmnopqrstuv";
const base: ApiTokenRecord = {
  id: "token-id",
  organization_id: "org-a",
  created_by: "user-a",
  scopes: ["releases:write"],
  project_ids: ["project-a"],
  expires_at: "2027-01-01T00:00:00.000Z",
  revoked_at: null,
};

Deno.test("API token SHA-256 digest is deterministic and never returns the secret", async () => {
  const digest = await hashApiToken(secret);
  assertEquals(digest.length, 64);
  assertEquals(digest, await hashApiToken(secret));
  assertEquals(digest === secret, false);
});

Deno.test("scoped API token accepts its organization, project and granted scope", () => {
  assertEquals(apiTokenAllows(base, secret, "org-a", "project-a", "releases:write", Date.parse("2026-11-14T00:00:00Z")), true);
});

Deno.test("organization-wide API token can be restricted by scope", () => {
  assertEquals(apiTokenAllows({ ...base, project_ids: [] }, secret, "org-a", "project-z", "releases:write"), true);
  assertEquals(apiTokenAllows({ ...base, project_ids: [] }, secret, "org-a", "project-z", "sboms:write"), false);
});

Deno.test("API token rejects wrong organization and project", () => {
  assertEquals(apiTokenAllows(base, secret, "org-b", "project-a", "releases:write"), false);
  assertEquals(apiTokenAllows(base, secret, "org-a", "project-b", "releases:write"), false);
});

Deno.test("API token rejects revoked and expired credentials", () => {
  assertEquals(apiTokenAllows({ ...base, revoked_at: "2026-11-13T00:00:00Z" }, secret, "org-a", "project-a", "releases:write"), false);
  assertEquals(apiTokenAllows({ ...base, expires_at: "2026-11-13T00:00:00Z" }, secret, "org-a", "project-a", "releases:write"), false);
});

Deno.test("API token rejects malformed prefixes and missing scopes", () => {
  assertEquals(apiTokenAllows(base, "not-a-token", "org-a", "project-a", "releases:write"), false);
  assertEquals(apiTokenAllows({ ...base, scopes: [] }, secret, "org-a", "project-a", "releases:write"), false);
});
