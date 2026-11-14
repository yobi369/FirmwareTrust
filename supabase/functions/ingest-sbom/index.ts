import { hashApiToken } from "./api_tokens.ts";
import { affectedRange, deduplicateComponents, normalizeCycloneDx, normalizeSpdx, purlHasVersion, severityOf } from "./sbom.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "apikey, authorization, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Max-Age": "86400"
};
function respond(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
}
async function persistScanStatus(supabaseUrl: string, headers: Record<string,string>, sbomId: string, status: string, scanned: number, findings: number, warning: string | null = null): Promise<boolean> {
  try {
    const response = await fetch(supabaseUrl + "/rest/v1/sbom_documents?id=eq." + sbomId, {
      method: "PATCH",
      headers: { ...headers, "Content-Type": "application/json", Prefer: "return=minimal" },
      body: JSON.stringify({ scan_status: status, scan_source: "OSV.dev", scanned_at: new Date().toISOString(), scanned_component_count: scanned, finding_count: findings, scan_warning: warning })
    });
    return response.ok;
  } catch { return false; }
}
async function mapLimit<T>(items: T[], limit: number, worker: (item: T) => Promise<void>) {
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) { const index = next++; if (index >= items.length) return; await worker(items[index]); }
  });
  await Promise.all(runners);
}
Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (request.method !== "POST") return respond({ error: "Method not allowed" }, 405);
  const authorization = request.headers.get("authorization") || "";
  const apiTokenMatch = authorization.match(/^Bearer (ft_live_[A-Za-z0-9_-]{43})$/);
  if (!apiTokenMatch && !/^Bearer\s+\S+$/i.test(authorization)) return respond({ error: "Authentication required" }, 401);
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 6 * 1024 * 1024) return respond({ error: "SBOM upload exceeds the 6 MB request limit" }, 413);
  let body: any;
  try { const raw = await request.text(); if (raw.length > 6 * 1024 * 1024) return respond({ error: "SBOM upload exceeds the 6 MB request limit" }, 413); body = JSON.parse(raw); }
  catch { return respond({ error: "Expected valid JSON request" }, 400); }
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (typeof body.organization_id !== "string" || !uuid.test(body.organization_id) || typeof body.project_id !== "string" || !uuid.test(body.project_id)) return respond({ error: "Valid organization_id and project_id are required" }, 400);
  if (body.release_id != null && (typeof body.release_id !== "string" || !uuid.test(body.release_id))) return respond({ error: "release_id must be a valid UUID" }, 400);
  if (typeof body.document_text !== "string" || body.document_text.length < 2) return respond({ error: "SBOM document text is missing" }, 400);
  const documentBytes = new TextEncoder().encode(body.document_text);
  if (documentBytes.byteLength > 5 * 1024 * 1024) return respond({ error: "SBOM document text exceeds 5 MB" }, 400);
  let document: any;
  try { document = JSON.parse(body.document_text); } catch { return respond({ error: "SBOM file is not valid JSON" }, 400); }
  let normalized: { format: string; specVersion: string; components: any[] };
  if (document.bomFormat === "CycloneDX" && Array.isArray(document.components)) normalized = normalizeCycloneDx(document);
  else if (typeof document.spdxVersion === "string" && document.spdxVersion.startsWith("SPDX-") && Array.isArray(document.packages)) normalized = normalizeSpdx(document);
  else return respond({ error: "Only CycloneDX JSON and SPDX JSON SBOMs are supported" }, 422);
  const components = deduplicateComponents(normalized.components);
  if (components.length < 1 || components.length > 20000) return respond({ error: "SBOM must contain between 1 and 20000 unique components" }, 422);
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const publishableRaw = Deno.env.get("SUPABASE_PUBLISHABLE_KEYS");
  const secretRaw = Deno.env.get("SUPABASE_SECRET_KEYS");
  if (!supabaseUrl || !publishableRaw) return respond({ error: "SBOM service is not configured" }, 503);
  let publishableKey: string;
  let secretKey: string | null = null;
  try { publishableKey = JSON.parse(publishableRaw).default; if (!publishableKey) throw new Error("Missing key"); }
  catch { return respond({ error: "SBOM service credentials are unavailable" }, 503); }
  const publicHeaders = { apikey: publishableKey, Authorization: "Bearer " + publishableKey, "Content-Type": "application/json" };
  let headers: Record<string,string>;
  let actorId: string;
  const apiToken = apiTokenMatch?.[1] ?? null;
  const apiTokenMode = apiToken !== null;
  try {
    if (apiToken) {
      try { secretKey = JSON.parse(secretRaw || "").default; } catch { secretKey = null; }
      if (!secretKey) return respond({ error: "Trusted SBOM API mode is not configured" }, 503);
      const serviceHeaders = { apikey: secretKey, Authorization: "Bearer " + secretKey, "Content-Type": "application/json" };
      const verifyResponse = await fetch(supabaseUrl + "/rest/v1/rpc/verify_api_token", {
        method: "POST", headers: publicHeaders,
        body: JSON.stringify({ raw_token: apiToken, required_scope: "sboms:write", target_project: body.project_id })
      });
      const verified = await verifyResponse.json().catch(() => null);
      if (!verifyResponse.ok || verified?.organization_id !== body.organization_id || typeof verified?.created_by !== "string") {
        return respond({ error: "API token is invalid or lacks SBOM access to this organization/project" }, verifyResponse.status === 403 ? 403 : 401);
      }
      const memberQuery = new URLSearchParams({ select: "role", organization_id: "eq." + body.organization_id, user_id: "eq." + verified.created_by, limit: "1" });
      const memberResponse = await fetch(supabaseUrl + "/rest/v1/organization_memberships?" + memberQuery.toString(), { headers: serviceHeaders });
      const memberships = await memberResponse.json().catch(() => null);
      if (!memberResponse.ok || !Array.isArray(memberships) || memberships.length !== 1 ||
          !["owner","admin","release_manager","developer","security_analyst"].includes(memberships[0].role)) {
        return respond({ error: "API token creator is no longer authorized to ingest SBOMs" }, 403);
      }
      actorId = verified.created_by;
      headers = serviceHeaders;
    } else {
      headers = { apikey: publishableKey, Authorization: authorization };
      const userResponse = await fetch(supabaseUrl + "/auth/v1/user", { headers });
      if (!userResponse.ok) return respond({ error: "Authenticated user session is invalid" }, 401);
      const user = await userResponse.json();
      if (!user?.id) return respond({ error: "Authenticated user identity is unavailable" }, 401);
      actorId = user.id;
    }
    const digestBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", documentBytes));
    const documentHash = Array.from(digestBytes, (byte) => byte.toString(16).padStart(2,"0")).join("");
    const apiTokenHash = apiToken ? await hashApiToken(apiToken) : null;
    const rpcPath = apiTokenMode ? "/rest/v1/rpc/ingest_sbom_for_api_with_token" : "/rest/v1/rpc/ingest_sbom";
    const rpcPayload = {
      ...(apiTokenMode ? { target_actor: actorId, target_api_token_hash: apiTokenHash } : {}),
      target_org: body.organization_id, target_project: body.project_id, target_release: body.release_id || null,
      target_format: normalized.format, target_spec_version: normalized.specVersion,
      target_document_sha256: documentHash, target_document: document, target_components: components
    };
    const rpcResponse = await fetch(supabaseUrl + rpcPath, {
      method: "POST", headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify(rpcPayload)
    });
    const rpcBody = await rpcResponse.json().catch(() => null);
    if (!rpcResponse.ok) return respond({ error: rpcBody?.message || "SBOM ingestion was rejected by tenant policy" }, rpcResponse.status >= 400 && rpcResponse.status < 500 ? rpcResponse.status : 502);
    const sbomId = typeof rpcBody === "string" ? rpcBody : rpcBody?.ingest_sbom || rpcBody?.ingest_sbom_for_api || rpcBody?.ingest_sbom_for_api_with_token;
    if (!sbomId) return respond({ error: "SBOM ingestion did not return a document ID" }, 502);

    const componentQuery = new URLSearchParams({ select: "id,component_name,version,purl", sbom_id: "eq." + sbomId, limit: "20000" });
    const componentResponse = await fetch(supabaseUrl + "/rest/v1/sbom_components?" + componentQuery.toString(), { headers });
    if (!componentResponse.ok) { const saved = await persistScanStatus(supabaseUrl, headers, sbomId, "not_started", 0, 0, "Component inventory could not be loaded for scanning"); return respond({ sbom_id: sbomId, component_count: components.length, scan_status: "not_started", scan_status_persisted: saved }, 201); }
    const savedComponents = await componentResponse.json();
    const componentMap = new Map<string, string>();
    for (const item of savedComponents) componentMap.set(String(item.purl || "") + "|" + item.component_name + "|" + String(item.version || ""), item.id);
    const candidates = components.filter((component) => typeof component.purl === "string" && component.purl.startsWith("pkg:") && (purlHasVersion(component.purl) || Boolean(component.version)));
    if (!candidates.length) { const saved = await persistScanStatus(supabaseUrl, headers, sbomId, "no_versioned_purls", 0, 0); return respond({ sbom_id: sbomId, format: normalized.format, component_count: components.length, scanned_components: 0, finding_count: 0, scan_status: "no_versioned_purls", scan_source: "OSV.dev", scan_status_persisted: saved }, 201); }
    const boundedCandidates = candidates.slice(0,1000);
    const queries = boundedCandidates.map((component) => { const purl = String(component.purl); return purlHasVersion(purl) ? { package: { purl } } : { package: { purl }, version: String(component.version) }; });
    let osvResponse: Response;
    try { osvResponse = await fetch("https://api.osv.dev/v1/querybatch", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ queries }) }); }
    catch { const saved = await persistScanStatus(supabaseUrl, headers, sbomId, "unavailable", boundedCandidates.length, 0, "OSV.dev querybatch network request failed"); return respond({ sbom_id: sbomId, format: normalized.format, component_count: components.length, scanned_components: boundedCandidates.length, finding_count: 0, scan_status: "unavailable", scan_source: "OSV.dev", scan_status_persisted: saved }, 201); }
    if (!osvResponse.ok) { const saved = await persistScanStatus(supabaseUrl, headers, sbomId, "unavailable", boundedCandidates.length, 0, "OSV.dev querybatch request failed"); return respond({ sbom_id: sbomId, format: normalized.format, component_count: components.length, scanned_components: boundedCandidates.length, finding_count: 0, scan_status: "unavailable", scan_source: "OSV.dev", scan_status_persisted: saved }, 201); }
    const batch = await osvResponse.json().catch(() => null);
    if (!Array.isArray(batch.results) || batch.results.length !== boundedCandidates.length) { const saved = await persistScanStatus(supabaseUrl, headers, sbomId, "partial", boundedCandidates.length, 0, "OSV returned an incomplete batch response"); return respond({ sbom_id: sbomId, format: normalized.format, component_count: components.length, scanned_components: boundedCandidates.length, finding_count: 0, scan_status: "partial", scan_source: "OSV.dev", scan_status_persisted: saved }, 201); }
    const mergedResults = batch.results.map((result: any) => ({ vulns: [...(result.vulns || [])], next_page_token: result.next_page_token || null }));
    let pendingPages = mergedResults.map((result: any, index: number) => result.next_page_token ? { index, token: result.next_page_token } : null).filter(Boolean) as { index: number; token: string }[];
    let paginationRounds = 0;
    while (pendingPages.length && paginationRounds < 5) {
      const pageQueries = pendingPages.map((page) => ({ ...queries[page.index], page_token: page.token }));
      let pageResponse: Response;
      try { pageResponse = await fetch("https://api.osv.dev/v1/querybatch", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ queries: pageQueries }) }); }
      catch { break; }
      if (!pageResponse.ok) break;
      const pageBody = await pageResponse.json().catch(() => null);
      if (!Array.isArray(pageBody?.results) || pageBody.results.length !== pendingPages.length) break;
      const nextPages: { index: number; token: string }[] = [];
      for (let pageIndex = 0; pageIndex < pendingPages.length; pageIndex++) {
        const page = pendingPages[pageIndex];
        const result = pageBody.results[pageIndex];
        mergedResults[page.index].vulns.push(...(result.vulns || []));
        if (result.next_page_token) nextPages.push({ index: page.index, token: result.next_page_token });
      }
      pendingPages = nextPages;
      paginationRounds++;
    }
    const querybatchHasMore = pendingPages.length > 0;
    const vulnerabilityComponents = new Map<string, Set<string>>();
    for (let index=0; index<boundedCandidates.length; index++) {
      const component = boundedCandidates[index];
      const componentId = componentMap.get(String(component.purl || "") + "|" + component.component_name + "|" + String(component.version || ""));
      if (!componentId) continue;
      for (const vuln of mergedResults[index].vulns) {
        if (!vuln.id) continue;
        if (!vulnerabilityComponents.has(vuln.id)) vulnerabilityComponents.set(vuln.id,new Set());
        vulnerabilityComponents.get(vuln.id)!.add(componentId);
      }
    }
    const allVulnerabilityIds = Array.from(vulnerabilityComponents.keys());
    const advisoriesTruncated = allVulnerabilityIds.length > 500;
    const vulnerabilityIds = allVulnerabilityIds.slice(0,500);
    const findings: any[] = [];
    let detailFailures = 0;
    await mapLimit(vulnerabilityIds,6,async (id) => {
      let detailResponse: Response;
      try { detailResponse = await fetch("https://api.osv.dev/v1/vulns/" + encodeURIComponent(id)); }
      catch { detailFailures++; return; }
      if (!detailResponse.ok) { detailFailures++; return; }
      const vuln = await detailResponse.json();
      const ranges = affectedRange(vuln);
      for (const componentId of vulnerabilityComponents.get(id) || []) findings.push({ organization_id: body.organization_id, sbom_id: sbomId, component_id: componentId, advisory_id: id, source: "OSV.dev", severity: severityOf(vuln), summary: String(vuln.summary || vuln.details || "").slice(0,4000) || null, affected_range: ranges.range, fixed_version: ranges.fixed, source_updated_at: vuln.modified || null });
    });
    let inserted = 0;
    if (findings.length) {
      const insertUrl = supabaseUrl + "/rest/v1/vulnerability_findings?on_conflict=sbom_id,advisory_id,source,component_id";
      for (let offset=0; offset<findings.length; offset+=500) {
        let insertResponse: Response;
        try { insertResponse = await fetch(insertUrl, { method: "POST", headers: { ...headers, "Content-Type": "application/json", Prefer: "resolution=ignore-duplicates,return=minimal" }, body: JSON.stringify(findings.slice(offset,offset+500)) }); }
        catch { detailFailures++; break; }
        if (!insertResponse.ok) { detailFailures++; break; }
        inserted += Math.min(500,findings.length-offset);
      }
    }
    const partial = candidates.length > boundedCandidates.length || detailFailures > 0 || querybatchHasMore || advisoriesTruncated;
    const finalStatus = partial ? "partial" : "complete";
    const saved = await persistScanStatus(supabaseUrl, headers, sbomId, finalStatus, boundedCandidates.length, inserted, partial ? "Some package or advisory results require a follow-up scan" : null);
    return respond({ sbom_id: sbomId, format: normalized.format, component_count: components.length, scanned_components: boundedCandidates.length, finding_count: inserted, scan_status: finalStatus, scan_source: "OSV.dev", advisory_details_failed: detailFailures, advisories_truncated: advisoriesTruncated, pagination_pending: querybatchHasMore, scan_status_persisted: saved }, 201);
  } catch { return respond({ error: "SBOM ingestion or vulnerability enrichment could not be completed" }, 503); }
});