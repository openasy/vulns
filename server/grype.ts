// Grype matches SBOMs against its vulnerability data (OS advisories, GitHub advisories, NVD, CISA KEV, EPSS).
// It runs as a child process with a fixed argument list and no shell.
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

export type Severity = "critical" | "high" | "medium" | "low" | "negligible" | "unknown";
export type FixState = "fixed" | "not-fixed" | "wont-fix" | "unknown";

export interface Match {
  vulnId: string;
  aliases: string[];
  pkgName: string;
  /** The source package it was built from, such as glibc for libc6 and libc-bin; the package itself otherwise. */
  pkgSource: string;
  pkgVersion: string;
  pkgType: string;
  purl: string | null;
  location: string | null;
  severity: Severity;
  cvss: number | null;
  epss: number | null;
  epssPercentile: number | null;
  kev: boolean;
  kevDue: string | null;
  ransomware: boolean;
  risk: number;
  fixState: FixState;
  fixedVersion: string | null;
  description: string | null;
  dataSource: string | null;
}

export interface Report {
  distro: string | null;
  matches: Match[];
}

export interface FeedStatus {
  /** Grype's database schema, e.g. "v6.1.10". */
  schema: string;
  /** When Anchore built this copy of the data. */
  built: string;
}

/** What the product needs from Grype; tests replace it. */
export interface Matcher {
  match(sbom: Buffer): Promise<Report>;
  /** The vulnerability data on disk, or null when there is none yet. */
  status(): Promise<FeedStatus | null>;
  /** Downloads newer data if there is any. Returns whether it changed. */
  update(): Promise<boolean>;
  /** Replaces the data with an archive from `grype db` (for air-gapped installs). */
  import(archive: string): Promise<void>;
}

const SEVERITIES = new Set<Severity>(["critical", "high", "medium", "low", "negligible", "unknown"]);
const FIX_STATES = new Set<FixState>(["fixed", "not-fixed", "wont-fix", "unknown"]);

type Raw = Record<string, any>;

const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : null);
const str = (v: unknown, max = 512) => (typeof v === "string" && v ? v.slice(0, max) : null);

/** Highest CVSS base score among the vulnerability and its aliases. */
function bestCvss(vulns: Raw[]): number | null {
  let best: number | null = null;
  for (const v of vulns)
    for (const c of Array.isArray(v?.cvss) ? v.cvss : []) {
      const s = num(c?.metrics?.baseScore);
      if (s !== null && (best === null || s > best)) best = s;
    }
  return best;
}

/** Turns `grype -o json` output into matches. Anything unexpected is dropped, not trusted. */
export function parseReport(raw: unknown): Report {
  const r = raw as Raw;
  if (!r || !Array.isArray(r.matches)) throw new Error("grype: output has no matches list");
  const distro = str(r.distro?.name) ? `${r.distro.name}${r.distro.version ? ` ${r.distro.version}` : ""}` : null;
  const matches: Match[] = [];
  for (const m of r.matches as Raw[]) {
    const v = m?.vulnerability as Raw | undefined;
    const a = m?.artifact as Raw | undefined;
    const vulnId = str(v?.id, 128);
    const pkgName = str(a?.name, 256);
    if (!v || !a || !vulnId || !pkgName) continue;
    const related: Raw[] = Array.isArray(m.relatedVulnerabilities) ? m.relatedVulnerabilities : [];
    const severity = String(v.severity ?? "unknown").toLowerCase() as Severity;
    const fixState = String(v.fix?.state ?? "unknown") as FixState;
    const epss = Array.isArray(v.epss) ? (v.epss[0] as Raw | undefined) : undefined;
    const kev = Array.isArray(v.knownExploited) ? (v.knownExploited as Raw[]) : [];
    matches.push({
      vulnId,
      aliases: [...new Set(related.map((x) => str(x?.id, 128)).filter((x): x is string => !!x && x !== vulnId))],
      pkgName,
      pkgSource: str(a.upstreams?.[0]?.name, 256) ?? pkgName,
      pkgVersion: str(a.version, 256) ?? "",
      pkgType: str(a.type, 32) ?? "unknown",
      purl: str(a.purl, 1024),
      location: str(a.locations?.[0]?.path, 1024),
      severity: SEVERITIES.has(severity) ? severity : "unknown",
      cvss: bestCvss([v, ...related]),
      epss: num(epss?.epss),
      epssPercentile: num(epss?.percentile),
      kev: kev.length > 0,
      kevDue: str(kev[0]?.dueDate, 32),
      ransomware: kev.some((k) => k?.knownRansomwareCampaignUse === "Known"),
      risk: num(v.risk) ?? 0,
      fixState: FIX_STATES.has(fixState) ? fixState : "unknown",
      fixedVersion: str(v.fix?.versions?.[0], 256),
      description: str(v.description ?? related.find((x) => x?.description)?.description, 2000),
      dataSource: str(v.dataSource, 1024),
    });
  }
  return { distro, matches };
}

interface Run {
  code: number | null;
  stdout: string;
  stderr: string;
}

export interface GrypeOptions {
  bin: string;
  /** Where the vulnerability data lives, on the data volume. */
  dataDir: string;
  /** Where SBOMs are written for Grype to read, on the data volume. */
  tmpDir: string;
  /** Mirror of grype.anchore.io for installs that cannot reach it. */
  updateUrl?: string;
  /** Killed after this long; matching a large SBOM takes seconds, an update a few minutes. */
  timeoutMs?: number;
}

export function createGrype({ bin, dataDir, tmpDir, updateUrl, timeoutMs = 10 * 60_000 }: GrypeOptions): Matcher {
  // Grype never updates itself or the data on its own, and never checks for new versions (ADR 0015):
  // the product decides when the data is downloaded.
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: dataDir,
    TMPDIR: process.env.TMPDIR ?? dataDir,
    GRYPE_DB_CACHE_DIR: dataDir,
    GRYPE_DB_AUTO_UPDATE: "false",
    // The product shows the data's age and warns when it is old, instead of refusing to match (air-gapped installs).
    GRYPE_DB_VALIDATE_AGE: "false",
    // The archive's checksum is verified when it is downloaded or imported; hashing 3 GB before every match is not needed.
    GRYPE_DB_VALIDATE_BY_HASH_ON_START: "false",
    GRYPE_DB_UPDATE_DOWNLOAD_TIMEOUT: "30m",
    GRYPE_CHECK_FOR_APP_UPDATE: "false",
    ...(updateUrl && { GRYPE_DB_UPDATE_URL: updateUrl }),
  };

  function run(args: string[]): Promise<Run> {
    return new Promise((resolve, reject) => {
      const child = spawn(bin, args, { env, stdio: ["ignore", "pipe", "pipe"], timeout: timeoutMs });
      const out: Buffer[] = [];
      const err: Buffer[] = [];
      child.stdout.on("data", (c: Buffer) => out.push(c));
      child.stderr.on("data", (c: Buffer) => err.push(c));
      child.on("error", reject);
      child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8").slice(-2000) }));
    });
  }

  const fail = (what: string, r: Run) => new Error(`grype ${what} failed (exit ${r.code}): ${r.stderr.trim().split("\n").pop()?.trim() ?? ""}`);

  return {
    async match(sbom) {
      // Grype reads SBOMs from a file: it only takes stdin from a FIFO, and Node's pipes are sockets.
      const file = join(tmpDir, `sbom-${randomUUID()}.json`);
      await writeFile(file, sbom, { mode: 0o600 });
      try {
        const r = await run([`sbom:${file}`, "-o", "json", "-q"]);
        if (r.code !== 0) throw fail("match", r);
        return parseReport(JSON.parse(r.stdout));
      } finally {
        await rm(file, { force: true });
      }
    },
    async status() {
      const r = await run(["db", "status", "-o", "json"]);
      if (r.code !== 0) return null;
      const s = JSON.parse(r.stdout) as Raw;
      return s.valid && typeof s.built === "string" ? { schema: String(s.schemaVersion), built: s.built } : null;
    },
    async update() {
      const before = await this.status();
      const r = await run(["db", "update", "-q"]);
      if (r.code !== 0) throw fail("db update", r);
      const after = await this.status();
      return after?.built !== before?.built;
    },
    async import(archive) {
      const r = await run(["db", "import", archive, "-q"]);
      if (r.code !== 0) throw fail("db import", r);
    },
  };
}
