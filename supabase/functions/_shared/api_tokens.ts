export interface ApiTokenRecord {
  id: string;
  organization_id: string;
  created_by: string;
  scopes: string[];
  project_ids: string[];
  expires_at: string;
  revoked_at: string | null;
}

export async function hashApiToken(secret: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function apiTokenAllows(
  record: ApiTokenRecord,
  secret: string,
  organizationId: string,
  projectId: string,
  requiredScope: string,
  now = Date.now(),
): boolean {
  if (!secret.startsWith("ft_live_") || record.revoked_at !== null) return false;
  if (!record.id || !record.created_by || record.organization_id !== organizationId) return false;
  if (!Array.isArray(record.scopes) || !record.scopes.includes(requiredScope)) return false;
  if (!Array.isArray(record.project_ids) || (record.project_ids.length > 0 && !record.project_ids.includes(projectId))) return false;
  const expiry = Date.parse(record.expires_at);
  if (!Number.isFinite(expiry) || expiry <= now) return false;
  return true;
}
