import { verifyEd25519Manifest } from "./verification.ts";
import { apiTokenAllows, hashApiToken, type ApiTokenRecord } from "../_shared/api_tokens.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "apikey, authorization, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Max-Age": "86400"
};

function respond(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }
  });
}


Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (request.method !== "POST") return respond({ error: "Method not allowed" }, 405);
  const authorization = request.headers.get("authorization") || "";
  if (!/^Bearer\s+\S+$/i.test(authorization)) return respond({ error: "Authentication required" }, 401);
  const contentLength = Number(request.headers.get("content-length") || "0");
  if (contentLength > 262144) return respond({ error: "Request body too large" }, 413);
  let body: Record<string, unknown>;
  try {
    const raw = await request.text();
    if (raw.length > 262144) return respond({ error: "Request body too large" }, 413);
    body = JSON.parse(raw);
  } catch { return respond({ error: "Expected valid JSON" }, 400); }

  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  const orgId = body.organization_id;
  const projectId = body.project_id;
  const version = body.version;
  const artifactName = body.artifact_name;
  const artifactSha = body.artifact_sha256;
  const manifest = body.manifest as Record<string, any> | undefined;
  if (typeof orgId !== "string" || !uuid.test(orgId) || typeof projectId !== "string" || !uuid.test(projectId)) {
    return respond({ error: "Valid organization_id and project_id are required" }, 400);
  }
  if (typeof version !== "string" || version.trim().length < 1 || version.length > 80
      || typeof artifactName !== "string" || artifactName.trim().length < 1 || artifactName.length > 255
      || typeof artifactSha !== "string" || !/^[a-f0-9]{64}$/i.test(artifactSha)) {
    return respond({ error: "A release version, artifact name and SHA-256 digest are required" }, 400);
  }
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest) || !manifest.signature || !manifest.artifact) {
    return respond({ error: "A signed FirmwareTrust release manifest is required" }, 400);
  }
  const trust = manifest.trust_registry;
  const signature = manifest.signature;
  const artifact = manifest.artifact;
  if (trust?.provider !== "firmwaretrust" || trust.organization_id !== orgId || trust.project_id !== projectId) {
    return respond({ error: "The signed manifest trust scope does not match the selected organization and project" }, 422);
  }
  if (signature.algorithm !== "Ed25519" || typeof signature.key_id !== "string" || !/^[a-f0-9]{16}$/i.test(signature.key_id)
      || typeof signature.value !== "string" || signature.value.length > 256) {
    return respond({ error: "Manifest signature metadata is invalid" }, 422);
  }
  if (artifact.filename !== artifactName || artifact.digest_algorithm !== "sha256"
      || typeof artifact.digest !== "string" || artifact.digest.toLowerCase() !== artifactSha.toLowerCase()
      || !Number.isSafeInteger(artifact.size_bytes) || artifact.size_bytes < 1) {
    return respond({ error: "Release metadata does not match the signed manifest" }, 422);
  }

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const publishableRaw = Deno.env.get("SUPABASE_PUBLISHABLE_KEYS");
  const secretRaw = Deno.env.get("SUPABASE_SECRET_KEYS");
  if (!supabaseUrl || !publishableRaw || !secretRaw) return respond({ error: "Release registry is not configured for trusted attestation" }, 503);
  let publishableKey: string;
  let secretKey: string;
  try {
    publishableKey = JSON.parse(publishableRaw).default;
    secretKey = JSON.parse(secretRaw).default;
    if (typeof publishableKey !== "string" || !publishableKey || typeof secretKey !== "string" || !secretKey) throw new Error("Missing default API keys");
  } catch { return respond({ error: "Release registry credentials are unavailable" }, 503); }
  const headers = { apikey: publishableKey, Authorization: authorization };
  const serviceHeaders = { apikey: secretKey, Authorization: "Bearer " + secretKey };

  try {
    let actorId: string;
    let lookupHeaders: Record<string, string> = headers;
    let apiTokenId: string | null = null;
    const userResponse = await fetch(supabaseUrl + "/auth/v1/user", { headers });
    if (userResponse.ok) {
      const user = await userResponse.json();
      if (!user?.id) return respond({ error: "Authenticated user identity is unavailable" }, 401);
      actorId = user.id;
    } else {
      const bearerToken = authorization.replace(/^Bearer\\s+/i, "");
      if (!bearerToken.startsWith("ft_live_")) return respond({ error: "Authentication required" }, 401);
      const tokenHash = await hashApiToken(bearerToken);
      const tokenQuery = new URLSearchParams({
        select: "id,organization_id,created_by,scopes,project_ids,expires_at,revoked_at",
        token_hash: "eq." + tokenHash,
        limit: "2"
      });
      const tokenResponse = await fetch(supabaseUrl + "/rest/v1/api_tokens?" + tokenQuery.toString(), { headers: serviceHeaders });
      if (!tokenResponse.ok) return respond({ error: "API token validation is unavailable" }, 503);
      const tokenRows = await tokenResponse.json();
      if (!Array.isArray(tokenRows) || tokenRows.length !== 1) return respond({ error: "API token is invalid" }, 401);
      const apiToken = tokenRows[0] as ApiTokenRecord;
      if (!apiTokenAllows(apiToken, bearerToken, orgId, projectId, "releases:write")) {
        return respond({ error: "API token is expired, revoked or outside its organization, project or scope" }, 403);
      }
      actorId = apiToken.created_by;
      apiTokenId = apiToken.id;
      lookupHeaders = serviceHeaders;
    }

    const membershipQuery = new URLSearchParams({
      select: "role",
      organization_id: "eq." + orgId,
      user_id: "eq." + actorId,
      limit: "1"
    });
    const membershipResponse = await fetch(supabaseUrl + "/rest/v1/organization_memberships?" + membershipQuery.toString(), { headers: lookupHeaders });
    if (!membershipResponse.ok) return respond({ error: "Organization membership validation failed" }, 502);
    const memberships = await membershipResponse.json();
    if (!Array.isArray(memberships) || memberships.length !== 1
        || !["owner", "admin", "release_manager", "developer"].includes(memberships[0].role)) {
      return respond({ error: "Your organization role cannot register releases" }, 403);
    }

    const projectQuery = new URLSearchParams({ select: "id", id: "eq." + projectId, organization_id: "eq." + orgId, limit: "1" });
    const projectResponse = await fetch(supabaseUrl + "/rest/v1/projects?" + projectQuery.toString(), { headers: lookupHeaders });
    if (!projectResponse.ok) return respond({ error: "Project membership validation failed" }, 502);
    const projects = await projectResponse.json();
    if (!Array.isArray(projects) || projects.length !== 1) return respond({ error: "Project does not belong to this organization" }, 404);

    const keyQuery = new URLSearchParams({
      select: "key_fingerprint,algorithm,public_key_pem,status,valid_from,valid_until",
      organization_id: "eq." + orgId,
      project_id: "eq." + projectId,
      key_fingerprint: "eq." + signature.key_id.toLowerCase(),
      limit: "2"
    });
    const keyResponse = await fetch(supabaseUrl + "/rest/v1/signing_keys?" + keyQuery.toString(), { headers: lookupHeaders });
    if (!keyResponse.ok) return respond({ error: "Signing-key registry lookup failed" }, 502);
    const keys = await keyResponse.json();
    if (!Array.isArray(keys) || keys.length !== 1) return respond({ error: "The signing key is not registered in this project" }, 422);
    const key = keys[0];
    const now = Date.now();
    const validFrom = Date.parse(key.valid_from);
    const validUntil = key.valid_until ? Date.parse(key.valid_until) : null;
    if (key.status !== "active" || key.algorithm !== "Ed25519" || !Number.isFinite(validFrom) || validFrom > now
        || (validUntil !== null && (!Number.isFinite(validUntil) || validUntil <= now))) {
      return respond({ error: "The signing key is not currently active and trusted", key_status: key.status }, 422);
    }

    let verification: { valid: boolean; manifestSha256: string; signatureSha256: string };
    try {
      verification = await verifyEd25519Manifest(manifest, String(key.public_key_pem));
    } catch {
      return respond({ error: "Manifest Ed25519 signature material is malformed" }, 422);
    }
    if (!verification.valid) return respond({ error: "Manifest Ed25519 signature verification failed" }, 422);
    const manifestDigest = verification.manifestSha256;
    const signatureDigest = verification.signatureSha256;

    const registrationResponse = await fetch(supabaseUrl + "/rest/v1/rpc/register_verified_release", {
      method: "POST",
      headers: { ...serviceHeaders, "Content-Type": "application/json" },
      body: JSON.stringify({
        target_org: orgId,
        target_project: projectId,
        target_version: version.trim(),
        target_artifact_name: artifactName.trim(),
        target_artifact_sha256: artifactSha.toLowerCase(),
        target_manifest: manifest,
        target_actor: actorId,
        target_key_fingerprint: signature.key_id.toLowerCase(),
        target_manifest_sha256: manifestDigest,
        target_signature_sha256: signatureDigest
      })
    });
    const registrationBody = await registrationResponse.json().catch(() => null);
    if (!registrationResponse.ok) {
      const message = registrationBody?.message || registrationBody?.details || "Trusted release registration failed";
      return respond({ error: message }, registrationResponse.status >= 400 && registrationResponse.status < 500 ? registrationResponse.status : 502);
    }
    if (apiTokenId) {
      try {
        await fetch(supabaseUrl + "/rest/v1/api_tokens?id=eq." + encodeURIComponent(apiTokenId) + "&revoked_at=is.null", {
          method: "PATCH",
          headers: { ...serviceHeaders, "Content-Type": "application/json", "Prefer": "return=minimal" },
          body: JSON.stringify({ last_used_at: new Date().toISOString() })
        });
      } catch { /* Usage telemetry must not invalidate a successfully registered release. */ }
    }
    return respond({
      release_id: registrationBody?.release_id,
      signature_verified: true,
      attestation_created: registrationBody?.attestation_created === true,
      key_status: "active",
      verifier_version: "register-release/v2",
      authentication_method: apiTokenId ? "api_token" : "user_session"
    }, 201);
  } catch {
    return respond({ error: "Release registration could not be completed" }, 503);
  }
});