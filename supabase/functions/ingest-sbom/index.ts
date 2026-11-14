const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "apikey, authorization, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Max-Age": "86400"
};
function respond(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
}
function normalizeCycloneDx(doc: any) {
  const rows: any[] = [];
  const walk = (items: any[]) => {
    for (const item of items || []) {
      const licenses = (item.licenses || []).map((entry: any) => entry.expression || entry.license?.id || entry.license?.name).filter(Boolean);
      const hashes: Record<string, string> = {};
      for (const hash of item.hashes || []) if (hash.alg && hash.content) hashes[String(hash.alg).toUpperCase()] = String(hash.content);
      if (item.name) rows.push({ component_name: String(item.name).slice(0,512), version: item.version ? String(item.version).slice(0,255) : null, purl: item.purl ? String(item.purl).slice(0,2048) : null, license_expression: licenses.join(" AND ").slice(0,2048) || null, hashes });
      if (Array.isArray(item.components)) walk(item.components);
    }
  };
  walk([...(doc.metadata?.component ? [doc.metadata.component] : []), ...(doc.components || [])]);
  return { format: "cyclonedx", specVersion: String(doc.specVersion || ""), components: rows };
}
function normalizeSpdx(doc: any) {
  const rows: any[] = [];
  for (const item of doc.packages || []) {
    if (!item.name) continue;
    const purlRef = (item.externalRefs || []).find((ref: any) => String(ref.referenceType || "").toLowerCase() === "purl" || (String(ref.referenceCategory || "").toUpperCase() === "PACKAGE-MANAGER" && String(ref.referenceLocator || "").startsWith("pkg:")));
    const hashes: Record<string, string> = {};
    for (const hash of item.checksums || []) if (hash.algorithm && hash.checksumValue) hashes[String(hash.algorithm).toUpperCase()] = String(hash.checksumValue);
    rows.push({ component_name: String(item.name).slice(0,512), version: item.versionInfo ? String(item.versionInfo).slice(0,255) : null, purl: purlRef?.referenceLocator ? String(purlRef.referenceLocator).slice(0,2048) : null, license_expression: String(item.licenseDeclared || item.licenseConcluded || "").slice(0,2048) || null, hashes });
  }
  return { format: "spdx", specVersion: String(doc.spdxVersion || ""), components: rows };
}
function purlHasVersion(purl: string): boolean {
  const path = purl.split(/[?#]/)[0];
  const slash = path.indexOf("/");
  return slash >= 0 && path.lastIndexOf("@") > slash;
}
function severityOf(vuln: any): string | null {
  const raw = String(vuln.database_specific?.severity || vuln.severity?.[0]?.score || "").toLowerCase();
  if (["critical","high","medium","low"].includes(raw)) return raw;
  const score = Number(raw);
  if (Number.isFinite(score) && raw !== "") return score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low";
  return null;
}
function affectedRange(vuln: any): { range: string | null; fixed: string | null } {
  const parts: string[] = [];
  let fixed: string | null = null;
  for (const affected of vuln.affected || []) for (const range of affected.ranges || []) {
    const events = (range.events || []).map((event: any) => {
      if (event.introduced !== undefined) return "introduced " + event.introduced;
      if (event.fixed !== undefined) { if (!fixed) fixed = String(event.fixed); return "fixed " + event.fixed; }
      if (event.last_affected !== undefined) return "last affected " + event.last_affected;
      if (event.limit !== undefined) return "limit " + event.limit;
      return "";
    }).filter(Boolean);
    if (events.length) parts.push(String(range.type || "range") + ": " + events.join(", "));
  }
  return { range: parts.join("; ").slice(0,4000) || null, fixed };
}
async function persistScanStatus(supabaseUrl: string, headers: Record<string,string>, sbomId: string, status: string, scanned: number, findings: number, warning: string | null = null): Promise<boolean> {
  const response = await fetch(supabaseUrl + "/rest/v1/sbom_documents?id=eq." + sbomId, {
    method: "PATCH",
    headers: { ...headers, "Content-Type": "application/json", Prefer: "return=minimal" },
    body: JSON.stringify({ scan_status: status, scan_source: "OSV.dev", scanned_at: new Date().toISOString(), scanned_component_count: scanned, finding_count: findings, scan_warning: warning })
  });
  return response.ok;
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
  if (!/^Bearer\s+\S+$/i.test(authorization)) return respond({ error: "Authentication required" }, 401);
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
  const unique = new Map<string, any>();
  for (const component of normalized.components) {
    const key = String(component.purl || "") + "|" + component.component_name + "|" + String(component.version || "");
    if (!unique.has(key)) unique.set(key, component);
  }
  const components = Array.from(unique.values());
  if (components.length < 1 || components.length > 20000) return respond({ error: "SBOM must contain between 1 and 20000 unique components" }, 422);
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const publishableRaw = Deno.env.get("SUPABASE_PUBLISHABLE_KEYS");
  if (!supabaseUrl || !publishableRaw) return respond({ error: "SBOM service is not configured" }, 503);
  let publishableKey: string;
  try { publishableKey = JSON.parse(publishableRaw).default; if (!publishableKey) throw new Error("Missing key"); }
  catch { return respond({ error: "SBOM service credentials are unavailable" }, 503); }
  const headers = { apikey: publishableKey, Authorization: authorization };
  try {
    const userResponse = await fetch(supabaseUrl + "/auth/v1/user", { headers });
    if (!userResponse.ok) return respond({ error: "Authenticated user session is invalid" }, 401);
    const user = await userResponse.json();
    if (!user?.id) return respond({ error: "Authenticated user identity is unavailable" }, 401);
    const digestBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", documentBytes));
    const documentHash = Array.from(digestBytes, (byte) => byte.toString(16).padStart(2,"0")).join("");
    const rpcResponse = await fetch(supabaseUrl + "/rest/v1/rpc/ingest_sbom", {
      method: "POST", headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify({ target_org: body.organization_id, target_project: body.project_id, target_release: body.release_id || null, target_format: normalized.format, target_spec_version: normalized.specVersion, target_document_sha256: documentHash, target_document: document, target_components: components })
    });
    const rpcBody = await rpcResponse.json().catch(() => null);
    if (!rpcResponse.ok) return respond({ error: rpcBody?.message || "SBOM ingestion was rejected by tenant policy" }, rpcResponse.status >= 400 && rpcResponse.status < 500 ? rpcResponse.status : 502);
    const sbomId = typeof rpcBody === "string" ? rpcBody : rpcBody?.ingest_sbom;
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
    const queries = boundedCandidates.map((component) => purlHasVersion(component.purl) ? { package: { purl: component.purl } } : { package: { purl: component.purl }, version: component.version });
    const osvResponse = await fetch("https://api.osv.dev/v1/querybatch", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ queries }) });
    if (!osvResponse.ok) { const saved = await persistScanStatus(supabaseUrl, headers, sbomId, "unavailable", boundedCandidates.length, 0, "OSV.dev querybatch request failed"); return respond({ sbom_id: sbomId, format: normalized.format, component_count: components.length, scanned_components: boundedCandidates.length, finding_count: 0, scan_status: "unavailable", scan_source: "OSV.dev", scan_status_persisted: saved }, 201); }
    const batch = await osvResponse.json();
    if (!Array.isArray(batch.results) || batch.results.length !== boundedCandidates.length) { const saved = await persistScanStatus(supabaseUrl, headers, sbomId, "partial", boundedCandidates.length, 0, "OSV returned an incomplete batch response"); return respond({ sbom_id: sbomId, format: normalized.format, component_count: components.length, scanned_components: boundedCandidates.length, finding_count: 0, scan_status: "partial", scan_source: "OSV.dev", scan_status_persisted: saved }, 201); }
    const querybatchHasMore = batch.results.some((result: any) => Boolean(result.next_page_token));
    const vulnerabilityComponents = new Map<string, Set<string>>();
    for (let index=0; index<boundedCandidates.length; index++) {
      const component = boundedCandidates[index];
      const componentId = componentMap.get(String(component.purl || "") + "|" + component.component_name + "|" + String(component.version || ""));
      if (!componentId) continue;
      for (const vuln of batch.results?.[index]?.vulns || []) {
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
      const detailResponse = await fetch("https://api.osv.dev/v1/vulns/" + encodeURIComponent(id));
      if (!detailResponse.ok) { detailFailures++; return; }
      const vuln = await detailResponse.json();
      const ranges = affectedRange(vuln);
      for (const componentId of vulnerabilityComponents.get(id) || []) findings.push({ organization_id: body.organization_id, sbom_id: sbomId, component_id: componentId, advisory_id: id, source: "OSV.dev", severity: severityOf(vuln), summary: String(vuln.summary || vuln.details || "").slice(0,4000) || null, affected_range: ranges.range, fixed_version: ranges.fixed, source_updated_at: vuln.modified || null });
    });
    let inserted = 0;
    if (findings.length) {
      const insertUrl = supabaseUrl + "/rest/v1/vulnerability_findings?on_conflict=sbom_id,advisory_id,source,component_id";
      for (let offset=0; offset<findings.length; offset+=500) {
        const insertResponse = await fetch(insertUrl, { method: "POST", headers: { ...headers, "Content-Type": "application/json", Prefer: "resolution=ignore-duplicates,return=minimal" }, body: JSON.stringify(findings.slice(offset,offset+500)) });
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