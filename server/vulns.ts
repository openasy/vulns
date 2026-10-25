import { randomUUID } from "node:crypto";
import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import { gunzipSync, gzipSync } from "node:zlib";
import type { FeedStatus, Match, Matcher, Severity } from "./grype.ts";
import { log } from "./log.ts";

export type ProblemCode =
  | "invalid-token"
  | "invalid-json"
  | "invalid-body"
  | "invalid-sbom"
  | "version-mismatch"
  | "not-found"
  | "conflict"
  | "not-configured"
  | "payload-too-large"
  | "internal-error";

export class VulnsError extends Error {
  readonly status: number;
  readonly code: ProblemCode;
  constructor(status: number, code: ProblemCode, detail: string) {
    super(detail);
    this.status = status;
    this.code = code;
  }
}

export type Kind = "host" | "image";
export type SbomFormat = "syft-json" | "cyclonedx-json" | "spdx-json";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "negligible", "unknown"];
const RANK = `CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'negligible' THEN 1 ELSE 0 END`;
const BY_RANK = ["unknown", "negligible", "low", "medium", "high", "critical"] as const;

// Host names, and image references such as ghcr.io/openasy/vulns:0.1.0 or registry:5000/app@sha256:….
const NAME = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,254}$/;
export const AGENT_ID = /^[a-z0-9][a-z0-9.-]{0,62}$/;
const VULN_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/;
const MAX_EXCEPTION_DAYS = 366;

const now = () => new Date().toISOString();
const DAY = 86_400_000;
const bad = (detail: string) => new VulnsError(422, "invalid-body", detail);
const notFound = (what: string) => new VulnsError(404, "not-found", `${what} does not exist.`);

/** Recognises the SBOM formats Grype reads and takes what the asset list shows from them. */
export function inspectSbom(body: unknown): { format: SbomFormat; packages: number; distro: string | null } {
  const b = body as Record<string, any>;
  if (!b || typeof b !== "object" || Array.isArray(b)) throw new VulnsError(422, "invalid-sbom", "The SBOM must be a JSON object.");
  if (Array.isArray(b.artifacts) && (b.descriptor?.name === "syft" || typeof b.schema?.version === "string")) {
    const d = b.distro ?? {};
    const distro =
      typeof d.prettyName === "string" && d.prettyName ? d.prettyName : typeof d.id === "string" && d.id ? `${d.id} ${d.versionID ?? ""}`.trim() : null;
    return { format: "syft-json", packages: b.artifacts.length, distro };
  }
  if (b.bomFormat === "CycloneDX") {
    const components: any[] = Array.isArray(b.components) ? b.components : [];
    const os = components.find((c) => c?.type === "operating-system");
    return {
      format: "cyclonedx-json",
      packages: components.filter((c) => c?.type !== "operating-system").length,
      distro: os ? `${os.name ?? ""} ${os.version ?? ""}`.trim() || null : null,
    };
  }
  if (typeof b.spdxVersion === "string" && Array.isArray(b.packages)) return { format: "spdx-json", packages: b.packages.length, distro: null };
  throw new VulnsError(422, "invalid-sbom", "Send a Syft JSON, CycloneDX JSON or SPDX JSON SBOM, for example from `syft <image> -o syft-json`.");
}

export interface Page<T> {
  items: T[];
  /** Opaque; pass it back as `cursor` for the next page. Absent on the last page (ADR 0024). */
  nextCursor?: string;
}

const encodeCursor = (offset: number) => Buffer.from(JSON.stringify({ o: offset })).toString("base64url");
function decodeCursor(cursor: string | undefined): number {
  if (!cursor) return 0;
  try {
    const o = (JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as { o?: unknown }).o;
    if (typeof o === "number" && Number.isSafeInteger(o) && o >= 0) return o;
  } catch {
    // fall through
  }
  throw bad("cursor is not one this API returned.");
}
export function parseLimit(value: string | null, max = 500, fallback = 100): number {
  if (value === null) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > max) throw bad(`limit must be between 1 and ${max}.`);
  return n;
}

export interface VulnFilter {
  status?: "open" | "excepted";
  severity?: Severity[];
  kev?: boolean;
  fixable?: boolean;
  kind?: Kind;
  assetId?: string;
  q?: string;
}

type Counts = Record<Severity, number>;
const zero = (): Counts => ({ critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0 });

export interface VulnsOptions {
  /** Resolved findings and expired exceptions older than this are deleted (ADR 0015). */
  retentionDays?: number;
}

export function createVulns(db: DatabaseSync, matcher: Matcher, { retentionDays = 90 }: VulnsOptions = {}) {
  const getSetting = (key: string) => (db.prepare("SELECT value FROM settings WHERE key = ?").get(key) as { value: string } | undefined)?.value;
  const setSetting = (key: string, value: string | null) =>
    value === null
      ? db.prepare("DELETE FROM settings WHERE key = ?").run(key)
      : db.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value").run(key, value);

  // Grype runs one at a time: matching loads the vulnerability data, and two copies would double the memory.
  let chain: Promise<unknown> = Promise.resolve();
  let queued = 0;
  function enqueue<T>(job: () => Promise<T>): Promise<T> {
    queued++;
    const next = chain.then(job).finally(() => queued--);
    chain = next.catch(() => {});
    return next;
  }

  let feed: FeedStatus | null = null;
  let feedChecked = false;
  let updating = false;

  async function refreshFeed() {
    feed = await matcher.status();
    feedChecked = true;
    return feed;
  }

  // ---- Matching

  const upsertFinding = db.prepare(
    `INSERT INTO findings (asset_id, vuln_id, pkg_name, pkg_version, pkg_type, pkg_source, purl, location, severity, cvss, epss, epss_percentile, kev, kev_due,
       ransomware, risk, fix_state, fixed_version, description, data_source, aliases, first_seen, last_seen, resolved_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
     ON CONFLICT (asset_id, vuln_id, pkg_name, pkg_version, pkg_type) DO UPDATE SET
       pkg_source = excluded.pkg_source, purl = excluded.purl, location = excluded.location, severity = excluded.severity, cvss = excluded.cvss, epss = excluded.epss,
       epss_percentile = excluded.epss_percentile, kev = excluded.kev, kev_due = excluded.kev_due, ransomware = excluded.ransomware,
       risk = excluded.risk, fix_state = excluded.fix_state, fixed_version = excluded.fixed_version, description = excluded.description,
       data_source = excluded.data_source, aliases = excluded.aliases, last_seen = excluded.last_seen,
       first_seen = CASE WHEN findings.resolved_at IS NULL THEN findings.first_seen ELSE excluded.first_seen END, resolved_at = NULL`,
  );

  function store(assetId: string, matches: Match[], distro: string | null) {
    const at = now();
    db.exec("BEGIN");
    try {
      // Grype can report one vulnerability twice for a package (several matchers); keep the first.
      const seen = new Set<string>();
      for (const m of matches) {
        const key = JSON.stringify([m.vulnId, m.pkgName, m.pkgVersion, m.pkgType]);
        if (seen.has(key)) continue;
        seen.add(key);
        upsertFinding.run(
          assetId,
          m.vulnId,
          m.pkgName,
          m.pkgVersion,
          m.pkgType,
          m.pkgSource,
          m.purl,
          m.location,
          m.severity,
          m.cvss,
          m.epss,
          m.epssPercentile,
          m.kev ? 1 : 0,
          m.kevDue,
          m.ransomware ? 1 : 0,
          m.risk,
          m.fixState,
          m.fixedVersion,
          m.description,
          m.dataSource,
          JSON.stringify(m.aliases),
          at,
          at,
        );
      }
      // Whatever matched before but not now is fixed, or no longer considered vulnerable.
      db.prepare("UPDATE findings SET resolved_at = ? WHERE asset_id = ? AND resolved_at IS NULL AND last_seen <> ?").run(at, assetId, at);
      db.prepare("UPDATE assets SET match_status = 'done', match_error = NULL, matched_at = ?, distro = COALESCE(?, distro) WHERE id = ?").run(
        at,
        distro,
        assetId,
      );
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }

  async function matchAsset(assetId: string) {
    const row = db.prepare("SELECT sbom FROM assets WHERE id = ?").get(assetId) as { sbom: Uint8Array } | undefined;
    if (!row) return; // deleted while queued
    if (!feedChecked) await refreshFeed();
    if (!feed) {
      db.prepare("UPDATE assets SET match_status = 'queued', match_error = ? WHERE id = ?").run(
        "Waiting for vulnerability data to be downloaded or imported.",
        assetId,
      );
      return;
    }
    db.prepare("UPDATE assets SET match_status = 'matching' WHERE id = ?").run(assetId);
    const started = performance.now();
    try {
      const report = await matcher.match(gunzipSync(row.sbom));
      if (!db.prepare("SELECT 1 FROM assets WHERE id = ?").get(assetId)) return;
      store(assetId, report.matches, report.distro);
      log("info", "asset matched", { asset: assetId, matches: report.matches.length, ms: Math.round(performance.now() - started) });
    } catch (err) {
      db.prepare("UPDATE assets SET match_status = 'failed', match_error = ? WHERE id = ?").run(String((err as Error).message).slice(0, 1000), assetId);
      log("warn", "matching failed", { asset: assetId, error: String(err) });
    }
  }

  function rematchAll() {
    const ids = (db.prepare("SELECT id FROM assets ORDER BY sbom_at").all() as Array<{ id: string }>).map((r) => r.id);
    db.prepare("UPDATE assets SET match_status = 'queued'").run();
    return Promise.all(ids.map((id) => enqueue(() => matchAsset(id))));
  }

  // ---- Assets

  type AssetRow = {
    id: string;
    kind: Kind;
    name: string;
    distro: string | null;
    packages: number;
    sbom_format: SbomFormat;
    sbom_at: string;
    match_status: string;
    match_error: string | null;
    matched_at: string | null;
    created_at: string;
    a_version: string | null;
    a_platform: string | null;
    a_last_seen: string | null;
    a_last_scan_at: string | null;
    a_last_error: string | null;
  };

  const ASSET_SELECT = `SELECT a.id, a.kind, a.name, a.distro, a.packages, a.sbom_format, a.sbom_at, a.match_status, a.match_error, a.matched_at, a.created_at,
      g.version AS a_version, g.platform AS a_platform, g.last_seen AS a_last_seen, g.last_scan_at AS a_last_scan_at, g.last_error AS a_last_error
    FROM assets a LEFT JOIN agents g ON a.kind = 'host' AND g.id = a.name`;

  const EXCEPTED = `EXISTS (SELECT 1 FROM exceptions e WHERE e.vuln_id = f.vuln_id AND (e.asset_id IS NULL OR e.asset_id = f.asset_id) AND e.expires_at > ?)`;

  /**
   * Open vulnerabilities at the end of each of the last 30 days (UTC), by severity, oldest first; today's is now, the
   * same as the summary's open. Grouped as the list groups them, without what an exception hid then.
   */
  function openByDay() {
    const at = now();
    const today = Math.floor(Date.parse(at) / DAY) * DAY;
    const query = db.prepare(
      `SELECT MAX(${RANK}) AS rank FROM findings f WHERE f.first_seen <= ? AND (f.resolved_at IS NULL OR f.resolved_at > ?)
         AND NOT EXISTS (SELECT 1 FROM exceptions e WHERE e.vuln_id = f.vuln_id AND (e.asset_id IS NULL OR e.asset_id = f.asset_id) AND e.created_at <= ? AND e.expires_at > ?)
       GROUP BY f.vuln_id, f.pkg_source, f.pkg_type`,
    );
    return Array.from({ length: 30 }, (_, i) => {
      const start = today - (29 - i) * DAY;
      const end = i === 29 ? at : new Date(start + DAY).toISOString();
      const open = zero();
      for (const g of query.all(end, end, end, end) as Array<{ rank: number }>) open[BY_RANK[g.rank]!]++;
      return { day: new Date(start).toISOString().slice(0, 10), open };
    });
  }

  function openCounts(assetIds: string[]): Map<string, { counts: Counts; kev: number; fixable: number }> {
    const out = new Map<string, { counts: Counts; kev: number; fixable: number }>();
    if (!assetIds.length) return out;
    const rows = db
      .prepare(
        `SELECT f.asset_id, f.severity, COUNT(*) AS n, SUM(f.kev) AS kev, SUM(f.fix_state = 'fixed') AS fixable FROM findings f
         WHERE f.resolved_at IS NULL AND NOT ${EXCEPTED} AND f.asset_id IN (${assetIds.map(() => "?").join(",")}) GROUP BY f.asset_id, f.severity`,
      )
      .all(now(), ...assetIds) as Array<{ asset_id: string; severity: Severity; n: number; kev: number; fixable: number }>;
    for (const r of rows) {
      const e = out.get(r.asset_id) ?? { counts: zero(), kev: 0, fixable: 0 };
      e.counts[r.severity] = r.n;
      e.kev += r.kev;
      e.fixable += r.fixable;
      out.set(r.asset_id, e);
    }
    return out;
  }

  function assetDto(r: AssetRow, counts?: { counts: Counts; kev: number; fixable: number }) {
    return {
      id: r.id,
      kind: r.kind,
      name: r.name,
      distro: r.distro,
      packages: r.packages,
      sbom: { format: r.sbom_format, receivedAt: r.sbom_at },
      match: { status: r.match_status, error: r.match_error, matchedAt: r.matched_at },
      open: counts?.counts ?? zero(),
      knownExploited: counts?.kev ?? 0,
      fixable: counts?.fixable ?? 0,
      createdAt: r.created_at,
      ...(r.kind === "host" && {
        agent: r.a_version
          ? { version: r.a_version, platform: r.a_platform, lastSeen: r.a_last_seen, lastScanAt: r.a_last_scan_at, lastError: r.a_last_error }
          : null,
      }),
    };
  }

  function asset(id: string) {
    const r = db.prepare(`${ASSET_SELECT} WHERE a.id = ?`).get(id) as AssetRow | undefined;
    if (!r) throw notFound("This asset");
    return assetDto(r, openCounts([id]).get(id));
  }

  return {
    enqueue,
    queueLength: () => queued,

    /** Stores an SBOM for a host or image and queues it for matching. `done` settles once it is matched. */
    ingest(kind: string | null, name: string | null, raw: Buffer) {
      if (kind !== "host" && kind !== "image") throw bad("kind must be host or image.");
      if (!name || !NAME.test(name)) throw bad("name must be a host name or image reference of at most 255 characters.");
      let body: unknown;
      try {
        body = JSON.parse(raw.toString("utf8"));
      } catch {
        throw new VulnsError(400, "invalid-json", "The SBOM must be JSON.");
      }
      const info = inspectSbom(body);
      const at = now();
      const sbom = gzipSync(raw);
      const existing = db.prepare("SELECT id FROM assets WHERE kind = ? AND name = ?").get(kind, name) as { id: string } | undefined;
      const id = existing?.id ?? randomUUID();
      if (existing) {
        db.prepare(
          "UPDATE assets SET sbom = ?, sbom_format = ?, sbom_at = ?, packages = ?, distro = COALESCE(?, distro), match_status = 'queued', match_error = NULL WHERE id = ?",
        ).run(sbom, info.format, at, info.packages, info.distro, id);
      } else {
        db.prepare(
          "INSERT INTO assets (id, kind, name, distro, packages, sbom, sbom_format, sbom_at, match_status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?)",
        ).run(id, kind, name, info.distro, info.packages, sbom, info.format, at, at);
      }
      if (kind === "host") db.prepare("UPDATE agents SET last_scan_at = ?, last_error = NULL WHERE id = ?").run(at, name);
      const done = enqueue(() => matchAsset(id)).then(() => asset(id));
      return { id, created: !existing, done };
    },

    listAssets(kind: string | null, cursor?: string, limit = 100): Page<ReturnType<typeof assetDto>> {
      if (kind !== null && kind !== "host" && kind !== "image") throw bad("kind must be host or image.");
      const offset = decodeCursor(cursor);
      const rows = db
        .prepare(`${ASSET_SELECT} ${kind ? "WHERE a.kind = ?" : ""} ORDER BY a.kind, a.name LIMIT ? OFFSET ?`)
        .all(...(kind ? [kind] : []), limit + 1, offset) as AssetRow[];
      const page = rows.slice(0, limit);
      const counts = openCounts(page.map((r) => r.id));
      return { items: page.map((r) => assetDto(r, counts.get(r.id))), ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }) };
    },

    asset,

    deleteAsset(id: string) {
      if (db.prepare("DELETE FROM assets WHERE id = ?").run(id).changes === 0) throw notFound("This asset");
    },

    /** The SBOM as it was received: your data, exportable (ADR 0015). */
    sbom(id: string) {
      const r = db.prepare("SELECT sbom, sbom_format FROM assets WHERE id = ?").get(id) as { sbom: Uint8Array; sbom_format: SbomFormat } | undefined;
      if (!r) throw notFound("This asset");
      return { body: gunzipSync(r.sbom), format: r.sbom_format };
    },

    /** Asks the host's agent to scan again; it hears about it on its next heartbeat. */
    requestScan(id: string) {
      const a = asset(id);
      if (a.kind !== "host") throw new VulnsError(409, "conflict", "Images are scanned when CI sends a new SBOM.");
      if (!a.agent) throw new VulnsError(409, "conflict", "This host has no vulns-agent; send a new SBOM instead.");
      db.prepare("UPDATE assets SET scan_requested = 1 WHERE id = ?").run(id);
    },

    // ---- Findings

    findings(assetId: string, status: "open" | "excepted" | "resolved", cursor?: string, limit = 100) {
      asset(assetId);
      const offset = decodeCursor(cursor);
      const where = status === "resolved" ? "f.resolved_at IS NOT NULL" : `f.resolved_at IS NULL AND ${status === "excepted" ? "" : "NOT "}${EXCEPTED}`;
      const rows = db
        .prepare(
          `SELECT f.*, ${RANK} AS rank FROM findings f WHERE f.asset_id = ? AND ${where}
           ORDER BY f.kev DESC, f.risk DESC, rank DESC, f.cvss DESC, f.vuln_id LIMIT ? OFFSET ?`,
        )
        .all(assetId, ...(status === "resolved" ? [] : [now()]), limit + 1, offset) as Array<Record<string, any>>;
      const items = rows.slice(0, limit).map((r) => ({
        vulnerability: r.vuln_id as string,
        aliases: JSON.parse(r.aliases) as string[],
        severity: r.severity as Severity,
        cvss: r.cvss as number | null,
        epss: r.epss as number | null,
        epssPercentile: r.epss_percentile as number | null,
        knownExploited: r.kev === 1,
        risk: r.risk as number,
        package: {
          name: r.pkg_name as string,
          source: r.pkg_source as string,
          version: r.pkg_version as string,
          type: r.pkg_type as string,
          purl: r.purl as string | null,
          location: r.location as string | null,
        },
        fix: { state: r.fix_state as string, version: r.fixed_version as string | null },
        description: r.description as string | null,
        firstSeen: r.first_seen as string,
        resolvedAt: r.resolved_at as string | null,
      }));
      return { items, ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }) };
    },

    /** Open findings grouped by vulnerability and package, most urgent first. */
    vulnerabilities(filter: VulnFilter, cursor?: string, limit = 100) {
      const offset = decodeCursor(cursor);
      const { sql, params } = groupedQuery(filter);
      const rows = db
        .prepare(`${sql} ORDER BY kev DESC, risk DESC, rank DESC, cvss DESC, vuln_id, pkg_source LIMIT ? OFFSET ?`)
        .all(...params, limit + 1, offset) as GroupRow[];
      return { items: rows.slice(0, limit).map(groupDto), ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }) };
    },

    vulnerability(vulnId: string) {
      const rows = db
        .prepare(
          `SELECT f.*, a.kind, a.name, ${EXCEPTED} AS excepted FROM findings f JOIN assets a ON a.id = f.asset_id
           WHERE f.vuln_id = ? AND f.resolved_at IS NULL ORDER BY a.kind, a.name`,
        )
        .all(now(), vulnId) as Array<Record<string, any>>;
      if (!rows.length) throw notFound("No open finding for this vulnerability, so it");
      const top = rows.reduce((a, b) => (b.risk > a.risk ? b : a));
      return {
        id: vulnId,
        aliases: JSON.parse(top.aliases) as string[],
        severity: BY_RANK[Math.max(...rows.map((r) => BY_RANK.indexOf(r.severity)))]!,
        cvss: top.cvss as number | null,
        epss: top.epss as number | null,
        epssPercentile: top.epss_percentile as number | null,
        knownExploited: rows.some((r) => r.kev === 1),
        kevDueDate: (rows.find((r) => r.kev_due)?.kev_due as string | undefined) ?? null,
        ransomware: rows.some((r) => r.ransomware === 1),
        risk: top.risk as number,
        description: top.description as string | null,
        dataSource: top.data_source as string | null,
        affected: rows.map((r) => ({
          asset: { id: r.asset_id as string, kind: r.kind as Kind, name: r.name as string },
          package: {
            name: r.pkg_name as string,
            source: r.pkg_source as string,
            version: r.pkg_version as string,
            type: r.pkg_type as string,
            purl: r.purl as string | null,
            location: r.location as string | null,
          },
          fix: { state: r.fix_state as string, version: r.fixed_version as string | null },
          excepted: r.excepted === 1,
          firstSeen: r.first_seen as string,
        })),
      };
    },

    /** What this product knows servers by, to say which in the hosts file it has nothing for (ADR 0052): host assets. */
    knownHosts(): string[] {
      return (db.prepare("SELECT name FROM assets WHERE kind = 'host'").all() as Array<{ name: string }>).map((r) => r.name);
    },

    summary() {
      const { sql, params } = groupedQuery({ status: "open" });
      const groups = db.prepare(sql).all(...params) as GroupRow[];
      const open = zero();
      for (const g of groups) open[BY_RANK[g.rank]!]++;
      const assets = db.prepare("SELECT kind, COUNT(*) AS n FROM assets GROUP BY kind").all() as Array<{ kind: Kind; n: number }>;
      const failed = db.prepare("SELECT COUNT(*) AS n FROM assets WHERE match_status = 'failed'").get() as { n: number };
      return {
        assets: { hosts: assets.find((a) => a.kind === "host")?.n ?? 0, images: assets.find((a) => a.kind === "image")?.n ?? 0, failed: failed.n },
        open,
        knownExploited: groups.filter((g) => g.kev === 1).length,
        fixable: groups.filter((g) => g.fixable === 1).length,
        feed: feedDto(),
        days: openByDay(),
      };
    },

    /**
     * What the overview draws besides the summary: vulnerabilities found and fixed each week, the assets and packages
     * with the most open ones, and how many of those have a fix.
     */
    overview() {
      const at = now();
      const first = Math.floor(Date.parse(at) / DAY) * DAY - 6 * DAY - 11 * 7 * DAY;
      const since = new Date(first).toISOString();
      // One pass each: the week a vulnerability was first found, and the week it was last fixed.
      const byWeek = (sql: string) => new Map((db.prepare(sql).all(first, 7 * DAY, since) as Array<{ w: number; n: number }>).map((r) => [r.w, r.n]));
      const found = byWeek(
        `SELECT w, COUNT(*) AS n FROM (SELECT vuln_id, CAST((unixepoch(MIN(first_seen), 'subsec') * 1000 - ?) / ? AS INTEGER) AS w FROM findings GROUP BY vuln_id HAVING MIN(first_seen) >= ?) GROUP BY w`,
      );
      const fixed = byWeek(
        `SELECT w, COUNT(*) AS n FROM (SELECT vuln_id, CAST((unixepoch(MAX(resolved_at), 'subsec') * 1000 - ?) / ? AS INTEGER) AS w FROM findings
           GROUP BY vuln_id HAVING COUNT(*) = COUNT(resolved_at) AND MAX(resolved_at) >= ?) GROUP BY w`,
      );
      const weeks = Array.from({ length: 12 }, (_, i) => ({
        week: new Date(first + i * 7 * DAY).toISOString().slice(0, 10),
        new: found.get(i) ?? 0,
        fixed: fixed.get(i) ?? 0,
      }));
      const topAssets = (
        db
          .prepare(
            // Vulnerabilities, not findings: a kernel CVE in seven installed kernel packages counts once.
            `SELECT a.id, a.kind, a.name, COUNT(DISTINCT f.vuln_id) FILTER (WHERE f.severity = 'critical') AS critical,
               COUNT(DISTINCT f.vuln_id) FILTER (WHERE f.severity = 'high') AS high, COUNT(DISTINCT f.vuln_id) AS open
             FROM findings f JOIN assets a ON a.id = f.asset_id WHERE f.resolved_at IS NULL AND NOT ${EXCEPTED}
             GROUP BY a.id ORDER BY critical DESC, high DESC, open DESC LIMIT 8`,
          )
          .all(at) as Array<{ id: string; kind: Kind; name: string; critical: number; high: number; open: number }>
      ).map((r) => ({ ...r }));
      const topPackages = (
        db
          .prepare(
            `SELECT f.pkg_name AS name, COUNT(DISTINCT f.vuln_id) AS open, MAX(${RANK}) AS rank, COUNT(DISTINCT f.asset_id) AS assets
             FROM findings f WHERE f.resolved_at IS NULL AND NOT ${EXCEPTED} GROUP BY f.pkg_name ORDER BY rank DESC, open DESC LIMIT 8`,
          )
          .all(at) as Array<{ name: string; open: number; rank: number; assets: number }>
      ).map((r) => ({ name: r.name, open: r.open, assets: r.assets, severity: BY_RANK[r.rank]! }));
      const fix = { fixed: 0, notFixed: 0, wontFix: 0 };
      // A vulnerability counts once, as fixed when any of its packages has a fix.
      for (const r of db
        .prepare(
          `SELECT state, COUNT(*) AS n FROM (
             SELECT CASE WHEN SUM(f.fix_state = 'fixed') > 0 THEN 'fixed' WHEN SUM(f.fix_state = 'wont-fix') > 0 THEN 'wont-fix' ELSE 'not-fixed' END AS state
             FROM findings f WHERE f.resolved_at IS NULL AND NOT ${EXCEPTED} GROUP BY f.vuln_id
           ) GROUP BY state`,
        )
        .all(at) as Array<{ state: string; n: number }>) {
        if (r.state === "fixed") fix.fixed += r.n;
        else if (r.state === "wont-fix") fix.wontFix += r.n;
        else fix.notFixed += r.n;
      }
      return { weeks, topAssets, topPackages, fix };
    },

    // ---- Exceptions

    listExceptions() {
      const rows = db.prepare("SELECT e.*, a.kind, a.name FROM exceptions e LEFT JOIN assets a ON a.id = e.asset_id ORDER BY e.expires_at").all() as Array<
        Record<string, any>
      >;
      const at = now();
      return rows.map((r) => ({
        id: r.id as string,
        vulnerability: r.vuln_id as string,
        asset: r.asset_id ? { id: r.asset_id as string, kind: r.kind as Kind, name: r.name as string } : null,
        reason: r.reason as string,
        createdAt: r.created_at as string,
        expiresAt: r.expires_at as string,
        active: r.expires_at > at,
      }));
    },

    createException(b: Record<string, unknown>) {
      const { vulnerability, assetId, reason, expiresAt } = b;
      if (typeof vulnerability !== "string" || !VULN_ID.test(vulnerability))
        throw bad("vulnerability must be an id such as CVE-2024-6387 or GHSA-xxxx-xxxx-xxxx.");
      if (assetId != null && (typeof assetId !== "string" || !db.prepare("SELECT 1 FROM assets WHERE id = ?").get(assetId)))
        throw bad("assetId must be an existing asset, or omitted for every asset.");
      if (typeof reason !== "string" || reason.trim().length < 3 || reason.length > 500) throw bad("reason must say why, in 3 to 500 characters.");
      const expires = typeof expiresAt === "string" ? Date.parse(expiresAt) : NaN;
      if (Number.isNaN(expires) || expires <= Date.now() || expires > Date.now() + MAX_EXCEPTION_DAYS * 86_400_000) {
        throw bad(`expiresAt must be a time in the next ${MAX_EXCEPTION_DAYS} days; an accepted risk is reviewed at least once a year.`);
      }
      const id = randomUUID();
      db.prepare("INSERT INTO exceptions (id, vuln_id, asset_id, reason, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)").run(
        id,
        vulnerability,
        (assetId as string | undefined) ?? null,
        reason.trim(),
        now(),
        new Date(expires).toISOString(),
      );
      return this.listExceptions().find((e) => e.id === id)!;
    },

    deleteException(id: string) {
      if (db.prepare("DELETE FROM exceptions WHERE id = ?").run(id).changes === 0) throw notFound("This exception");
    },

    // ---- Agents

    /** Records an agent's heartbeat. Returns whether someone asked for a scan of its host. */
    heartbeat(id: string, version: string, platform: "container" | "kubernetes", lastScanAt: string | null, lastError: string | null): boolean {
      db.prepare(
        `INSERT INTO agents (id, version, platform, last_seen, last_scan_at, last_error) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET version = excluded.version, platform = excluded.platform, last_seen = excluded.last_seen,
           last_scan_at = COALESCE(excluded.last_scan_at, agents.last_scan_at), last_error = excluded.last_error`,
      ).run(id, version, platform, now(), lastScanAt, lastError);
      const requested = db.prepare("UPDATE assets SET scan_requested = 0 WHERE kind = 'host' AND name = ? AND scan_requested = 1").run(id);
      return requested.changes > 0;
    },

    countAgents: () => (db.prepare("SELECT COUNT(*) AS n FROM agents").get() as { n: number }).n,

    // ---- Vulnerability data

    feed: feedDto,
    refreshFeed,

    /** Downloads newer vulnerability data and matches every asset again when it changed. */
    updateFeed(): Promise<boolean> {
      if (updating) return Promise.resolve(false);
      updating = true;
      setSetting("feed_error", null);
      return enqueue(async () => {
        try {
          const changed = await matcher.update();
          await refreshFeed();
          setSetting("feed_checked_at", now());
          if (changed) {
            setSetting("feed_updated_at", now());
            log("info", "vulnerability data updated", { built: feed?.built });
          }
          return changed;
        } catch (err) {
          setSetting("feed_error", String((err as Error).message).slice(0, 1000));
          log("warn", "could not update the vulnerability data", { error: String(err) });
          throw err;
        } finally {
          updating = false;
        }
      }).then(async (changed) => {
        if (changed) void rematchAll();
        return changed;
      });
    },

    async importFeed(archive: string) {
      await enqueue(async () => {
        await matcher.import(archive);
        await refreshFeed();
        setSetting("feed_updated_at", now());
        setSetting("feed_error", null);
      });
      log("info", "vulnerability data imported", { built: feed?.built });
      void rematchAll();
      return feedDto();
    },

    rematchAll,

    /** Deletes resolved findings and expired exceptions past the retention period. */
    purge() {
      const before = new Date(Date.now() - retentionDays * 86_400_000).toISOString();
      const f = db.prepare("DELETE FROM findings WHERE resolved_at IS NOT NULL AND resolved_at < ?").run(before).changes;
      const e = db.prepare("DELETE FROM exceptions WHERE expires_at < ?").run(before).changes;
      if (f || e) log("info", "retention applied", { findings: f, exceptions: e, retentionDays });
    },

    severityTotals() {
      const rows = db
        .prepare(`SELECT f.severity, COUNT(*) AS n FROM findings f WHERE f.resolved_at IS NULL AND NOT ${EXCEPTED} GROUP BY f.severity`)
        .all(now()) as Array<{ severity: Severity; n: number }>;
      const out = zero();
      for (const r of rows) out[r.severity] = r.n;
      return out;
    },
  };

  function feedDto() {
    const built = feed?.built ?? null;
    return {
      schema: feed?.schema ?? null,
      built,
      ageHours: built ? Math.floor((Date.now() - Date.parse(built)) / 3_600_000) : null,
      updatedAt: getSetting("feed_updated_at") ?? null,
      checkedAt: getSetting("feed_checked_at") ?? null,
      updating,
      error: getSetting("feed_error") ?? null,
    };
  }

  type GroupRow = {
    vuln_id: string;
    pkg_source: string;
    pkg_names: string;
    pkg_type: string;
    rank: number;
    cvss: number | null;
    epss: number | null;
    epss_percentile: number | null;
    kev: number;
    kev_due: string | null;
    ransomware: number;
    risk: number;
    versions: string;
    fixable: number;
    fix_state: string;
    fixed_version: string | null;
    description: string | null;
    aliases: string;
    first_seen: string;
    hosts: number;
    images: number;
  };

  function groupedQuery(filter: VulnFilter): { sql: string; params: SQLInputValue[] } {
    const where = ["f.resolved_at IS NULL", `${filter.status === "excepted" ? "" : "NOT "}${EXCEPTED}`];
    const params: SQLInputValue[] = [now()];
    if (filter.severity?.length) {
      where.push(`f.severity IN (${filter.severity.map(() => "?").join(",")})`);
      params.push(...filter.severity);
    }
    if (filter.kev) where.push("f.kev = 1");
    if (filter.fixable) where.push("f.fix_state = 'fixed'");
    if (filter.kind) (where.push("a.kind = ?"), params.push(filter.kind));
    if (filter.assetId) (where.push("f.asset_id = ?"), params.push(filter.assetId));
    if (filter.q) {
      where.push("(f.vuln_id LIKE ? ESCAPE '\\' OR f.pkg_name LIKE ? ESCAPE '\\' OR f.pkg_source LIKE ? ESCAPE '\\' OR f.aliases LIKE ? ESCAPE '\\')");
      const like = `%${filter.q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
      params.push(like, like, like, like);
    }
    const sql = `SELECT f.vuln_id, f.pkg_source, GROUP_CONCAT(DISTINCT f.pkg_name) AS pkg_names, f.pkg_type, MAX(${RANK}) AS rank, MAX(f.cvss) AS cvss, MAX(f.epss) AS epss, MAX(f.epss_percentile) AS epss_percentile,
        MAX(f.kev) AS kev, MAX(f.kev_due) AS kev_due, MAX(f.ransomware) AS ransomware, MAX(f.risk) AS risk, GROUP_CONCAT(DISTINCT f.pkg_version) AS versions,
        MAX(f.fix_state = 'fixed') AS fixable,
        CASE WHEN SUM(f.fix_state = 'fixed') > 0 THEN 'fixed' WHEN SUM(f.fix_state = 'wont-fix') > 0 THEN 'wont-fix'
             WHEN SUM(f.fix_state = 'not-fixed') > 0 THEN 'not-fixed' ELSE 'unknown' END AS fix_state,
        MAX(f.fixed_version) AS fixed_version, MAX(f.description) AS description, MAX(f.aliases) AS aliases, MIN(f.first_seen) AS first_seen,
        COUNT(DISTINCT CASE WHEN a.kind = 'host' THEN f.asset_id END) AS hosts, COUNT(DISTINCT CASE WHEN a.kind = 'image' THEN f.asset_id END) AS images
      FROM findings f JOIN assets a ON a.id = f.asset_id WHERE ${where.join(" AND ")} GROUP BY f.vuln_id, f.pkg_source, f.pkg_type`;
    return { sql, params };
  }

  function groupDto(g: GroupRow) {
    return {
      vulnerability: g.vuln_id,
      aliases: JSON.parse(g.aliases) as string[],
      package: { name: g.pkg_source, type: g.pkg_type, packages: g.pkg_names.split(",").sort(), versions: g.versions.split(",") },
      severity: BY_RANK[g.rank]!,
      cvss: g.cvss,
      epss: g.epss,
      epssPercentile: g.epss_percentile,
      knownExploited: g.kev === 1,
      kevDueDate: g.kev_due,
      ransomware: g.ransomware === 1,
      risk: g.risk,
      fix: { state: g.fix_state, version: g.fixed_version },
      description: g.description,
      hosts: g.hosts,
      images: g.images,
      firstSeen: g.first_seen,
    };
  }
}

export type Vulns = ReturnType<typeof createVulns>;
export { SEVERITIES };
