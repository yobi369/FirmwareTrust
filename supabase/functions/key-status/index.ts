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
};

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (request.method !== "POST") return respond({ error: "Method not allowed" }, 405);
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 2048) return respond({ error: "Request body too large" }, 413);
  let body: { organization_id?: unknown; project_id?: unknown; key_id?: unknown };
  try {
    const raw = await request.text();
    if (raw.length > 2048) return respond({ error: "Request body too large" }, 413);
    body = JSON.parse(raw);
  } catch { return respond({ error: "Expected a valid JSON request" }, 400); }
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (typeof body.organization_id !== "string" || !uuid.test(body.organization_id)
      || typeof body.project_id !== "string" || !uuid.test(body.project_id)
      || typeof body.key_id !== "string" || !/^[a-f0-9]{16}$/i.test(body.key_id)) {
    return respond({ error: "A valid organization_id, project_id and 16-character key_id are required" }, 400);
  }
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const secretMapRaw = Deno.env.get("SUPABASE_SECRET_KEYS");
  if (!supabaseUrl || !secretMapRaw) return respond({ error: "Trust registry is not configured" }, 503);
  let secretKey: string;
  try {
    const secretMap = JSON.parse(secretMapRaw);
    secretKey = secretMap.default;
    if (typeof secretKey !== "string" || !secretKey) throw new Error("Missing default secret key");
  } catch { return respond({ error: "Trust registry credentials are unavailable" }, 503); }
  const query = new URLSearchParams({
    select: "status,valid_from,valid_until,algorithm,key_fingerprint",
    organization_id: "eq." + body.organization_id,
    project_id: "eq." + body.project_id,
    key_fingerprint: "eq." + body.key_id,
    limit: "2"
  });
  try {
    const result = await fetch(supabaseUrl + "/rest/v1/signing_keys?" + query.toString(), {
      headers: { apikey: secretKey, Authorization: "Bearer " + secretKey }
    });
    if (!result.ok) return respond({ error: "Trust registry lookup failed" }, 502);
    const rows = await result.json();
    if (!Array.isArray(rows) || rows.length === 0) return respond({ trusted: false, status: "not_registered" });
    if (rows.length !== 1) return respond({ trusted: false, status: "ambiguous" });
    const row = rows[0];
    const now = Date.now();
    const validFrom = Date.parse(row.valid_from);
    const validUntil = row.valid_until ? Date.parse(row.valid_until) : null;
    const active = row.status === "active" && Number.isFinite(validFrom) && validFrom <= now
      && (validUntil === null || (Number.isFinite(validUntil) && validUntil > now));
    return respond({ trusted: active, status: active ? "active" : row.status, algorithm: row.algorithm, key_id: row.key_fingerprint, checked_at: new Date(now).toISOString() });
  } catch { return respond({ error: "Trust registry is temporarily unavailable" }, 503); }
});