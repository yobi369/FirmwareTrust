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

function canonical(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return "{" + Object.keys(record).sort().map((key) => JSON.stringify(key) + ":" + canonical(record[key])).join(",") + "}";
  }
  return JSON.stringify(value);
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
  if (!supabaseUrl || !publishableRaw) return respond({ error: "Release registry is not configured" }, 503);
  let publishableKey: string;
  try {
    publishableKey = JSON.parse(publishableRaw).default;
    if (typeof publishableKey !== "string" || !publishableKey) throw new Error("Missing default publishable key");
  } catch { return respond({ error: "Release registry credentials are unavailable" }, 503); }
  const headers = { apikey: publishableKey, Authorization: authorization };

  try {
    const userResponse = await fetch(supabaseUrl + "/auth/v1/user", { headers });
    if (!userResponse.ok) return respond({ error: "Authenticated user session is invalid" }, 401);
    const user = await userResponse.json();
    if (!user?.id) return respond({ error: "Authenticated user identity is unavailable" }, 401);

    const keyQuery = new URLSearchParams({
      select: "key_fingerprint,algorithm,public_key_pem,status,valid_from,valid_until",
      organization_id: "eq." + orgId,
      project_id: "eq." + projectId,
      key_fingerprint: "eq." + signature.key_id.toLowerCase(),
      limit: "2"
    });
    const keyResponse = await fetch(supabaseUrl + "/rest/v1/signing_keys?" + keyQuery.toString(), { headers });
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

    const pemMatch = String(key.public_key_pem).match(/-----BEGIN PUBLIC KEY-----([\\s\\S]+?)-----END PUBLIC KEY-----/);
    if (!pemMatch) return respond({ error: "Registered public key PEM is invalid" }, 500);
    const der = Uint8Array.from(atob(pemMatch[1].replace(/\\s/g, "")), (character) => character.charCodeAt(0));
    const publicKey = await crypto.subtle.importKey("spki", der, { name: "Ed25519" }, false, ["verify"]);
    const payload = JSON.parse(JSON.stringify(manifest));
    delete payload.signature.value;
    const signatureBytes = Uint8Array.from(atob(signature.value), (character) => character.charCodeAt(0));
    const valid = await crypto.subtle.verify({ name: "Ed25519" }, publicKey, signatureBytes, new TextEncoder().encode(canonical(payload)));
    if (!valid) return respond({ error: "Manifest Ed25519 signature verification failed" }, 422);

    const releaseResponse = await fetch(supabaseUrl + "/rest/v1/releases", {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/json", Prefer: "return=representation" },
      body: JSON.stringify({
        organization_id: orgId, project_id: projectId, version: version.trim(),
        artifact_name: artifactName.trim(), artifact_sha256: artifactSha.toLowerCase(),
        manifest, status: "draft", created_by: user.id
      })
    });
    const releaseBody = await releaseResponse.json().catch(() => null);
    if (!releaseResponse.ok) {
      const message = releaseBody?.message || releaseBody?.details || "Release registration was rejected";
      return respond({ error: message }, releaseResponse.status >= 400 && releaseResponse.status < 500 ? releaseResponse.status : 502);
    }
    return respond({ release: Array.isArray(releaseBody) ? releaseBody[0] : releaseBody, signature_verified: true, key_status: "active" }, 201);
  } catch {
    return respond({ error: "Release registration could not be completed" }, 503);
  }
});