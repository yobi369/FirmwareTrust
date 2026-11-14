export type NormalizedComponent = {
  component_name: string;
  version: string | null;
  purl: string | null;
  license_expression: string | null;
  hashes: Record<string, string>;
};

export type NormalizedSbom = {
  format: "cyclonedx" | "spdx";
  specVersion: string;
  components: NormalizedComponent[];
};

export function normalizeCycloneDx(doc: any): NormalizedSbom {
  const rows: NormalizedComponent[] = [];
  const walk = (items: any[]) => {
    for (const item of items || []) {
      const licenses = (item.licenses || [])
        .map((entry: any) => entry.expression || entry.license?.id || entry.license?.name)
        .filter(Boolean);
      const hashes: Record<string, string> = {};
      for (const hash of item.hashes || []) {
        if (hash.alg && hash.content) hashes[String(hash.alg).toUpperCase()] = String(hash.content);
      }
      if (item.name) rows.push({
        component_name: String(item.name).slice(0, 512),
        version: item.version ? String(item.version).slice(0, 255) : null,
        purl: item.purl ? String(item.purl).slice(0, 2048) : null,
        license_expression: licenses.join(" AND ").slice(0, 2048) || null,
        hashes
      });
      if (Array.isArray(item.components)) walk(item.components);
    }
  };
  walk([...(doc.metadata?.component ? [doc.metadata.component] : []), ...(doc.components || [])]);
  return { format: "cyclonedx", specVersion: String(doc.specVersion || ""), components: rows };
}

export function normalizeSpdx(doc: any): NormalizedSbom {
  const rows: NormalizedComponent[] = [];
  for (const item of doc.packages || []) {
    if (!item.name) continue;
    const purlRef = (item.externalRefs || []).find((ref: any) =>
      String(ref.referenceType || "").toLowerCase() === "purl"
      || (String(ref.referenceCategory || "").toUpperCase() === "PACKAGE-MANAGER"
        && String(ref.referenceLocator || "").startsWith("pkg:"))
    );
    const hashes: Record<string, string> = {};
    for (const hash of item.checksums || []) {
      if (hash.algorithm && hash.checksumValue) hashes[String(hash.algorithm).toUpperCase()] = String(hash.checksumValue);
    }
    rows.push({
      component_name: String(item.name).slice(0, 512),
      version: item.versionInfo ? String(item.versionInfo).slice(0, 255) : null,
      purl: purlRef?.referenceLocator ? String(purlRef.referenceLocator).slice(0, 2048) : null,
      license_expression: String(item.licenseDeclared || item.licenseConcluded || "").slice(0, 2048) || null,
      hashes
    });
  }
  return { format: "spdx", specVersion: String(doc.spdxVersion || ""), components: rows };
}

export function deduplicateComponents(rows: NormalizedComponent[]): NormalizedComponent[] {
  const unique = new Map<string, NormalizedComponent>();
  for (const component of rows) {
    const key = String(component.purl || "") + "|" + component.component_name + "|" + String(component.version || "");
    if (!unique.has(key)) unique.set(key, component);
  }
  return Array.from(unique.values());
}

export function purlHasVersion(purl: string): boolean {
  const path = purl.split(/[?#]/)[0];
  const slash = path.indexOf("/");
  if (slash < 0) return false;
  const packagePath = path.slice(slash + 1);
  const lastPackageSlash = packagePath.lastIndexOf("/");
  return packagePath.lastIndexOf("@") > lastPackageSlash;
}

export function severityOf(vuln: any): string | null {
  const raw = String(vuln.database_specific?.severity || vuln.severity?.[0]?.score || "").toLowerCase();
  if (["critical", "high", "medium", "low"].includes(raw)) return raw;
  const score = Number(raw);
  if (Number.isFinite(score) && raw !== "") return score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low";
  return null;
}

export function affectedRange(vuln: any): { range: string | null; fixed: string | null } {
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
  return { range: parts.join("; ").slice(0, 4000) || null, fixed };
}
