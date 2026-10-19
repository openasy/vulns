// The UI is an ordinary client of the public API (ADR 0014, 0018). Types follow openapi.json.

export type Severity = "critical" | "high" | "medium" | "low" | "negligible" | "unknown";
export type Kind = "host" | "image";
export type Counts = Record<Severity, number>;

export interface Fix {
  state: "fixed" | "not-fixed" | "wont-fix" | "unknown";
  version: string | null;
}

export interface Feed {
  schema: string | null;
  built: string | null;
  ageHours: number | null;
  updatedAt: string | null;
  checkedAt: string | null;
  updating: boolean;
  error: string | null;
}

export interface Summary {
  assets: { hosts: number; images: number; failed: number };
  open: Counts;
  knownExploited: number;
  fixable: number;
  feed: Feed;
}

export interface Vulnerability {
  vulnerability: string;
  aliases: string[];
  /** Source package (glibc), the installed packages built from it (libc6, libc-bin) and their versions. */
  package: { name: string; type: string; packages: string[]; versions: string[] };
  severity: Severity;
  cvss: number | null;
  epss: number | null;
  epssPercentile: number | null;
  knownExploited: boolean;
  kevDueDate: string | null;
  ransomware: boolean;
  risk: number;
  fix: Fix;
  description: string | null;
  hosts: number;
  images: number;
  firstSeen: string;
}

export interface Package {
  name: string;
  source: string;
  version: string;
  type: string;
  purl: string | null;
  location: string | null;
}

export interface VulnerabilityDetail {
  id: string;
  aliases: string[];
  severity: Severity;
  cvss: number | null;
  epss: number | null;
  knownExploited: boolean;
  kevDueDate: string | null;
  ransomware: boolean;
  description: string | null;
  dataSource: string | null;
  affected: Array<{ asset: { id: string; kind: Kind; name: string }; package: Package; fix: Fix; excepted: boolean; firstSeen: string }>;
}

export interface Asset {
  id: string;
  kind: Kind;
  name: string;
  distro: string | null;
  packages: number;
  sbom: { format: string; receivedAt: string };
  match: { status: "queued" | "matching" | "done" | "failed"; error: string | null; matchedAt: string | null };
  open: Counts;
  knownExploited: number;
  fixable: number;
  agent?: { version: string; platform: "container" | "kubernetes"; lastSeen: string; lastScanAt: string | null; lastError: string | null } | null;
}

export interface Finding {
  vulnerability: string;
  severity: Severity;
  cvss: number | null;
  epss: number | null;
  knownExploited: boolean;
  risk: number;
  package: Package;
  fix: Fix;
  description: string | null;
  firstSeen: string;
  resolvedAt: string | null;
}

export interface Exception {
  id: string;
  vulnerability: string;
  asset: { id: string; kind: Kind; name: string } | null;
  reason: string;
  createdAt: string;
  expiresAt: string;
  active: boolean;
}

export class Unauthorized extends Error {}
export class ApiError extends Error {}

// Until sign-in exists (ADR 0002), the UI uses VULNS_ADMIN_TOKEN, kept only for this browser tab.
const TOKEN_KEY = "vulns-admin-token";
export const readToken = () => {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
};
export const saveToken = (t: string) => {
  try {
    if (t) sessionStorage.setItem(TOKEN_KEY, t);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // Storage blocked: the token lasts until the page reloads.
  }
};

export async function api<T>(path: string, token: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, { ...init, headers: { ...(token && { authorization: `Bearer ${token}` }), ...(init.body ? { "content-type": "application/json" } : {}), ...init.headers } });
  if (res.status === 401 || res.status === 503) throw new Unauthorized(((await res.json().catch(() => ({}))) as { detail?: string }).detail);
  if (!res.ok) throw new ApiError(((await res.json().catch(() => ({}))) as { detail?: string }).detail ?? `${path}: ${res.status}`);
  return (res.status === 204 ? undefined : await res.json()) as T;
}
