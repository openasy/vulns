import { timingSafeEqual } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdir, readFile, rm } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { extname, join, normalize } from "node:path";
import { pipeline } from "node:stream/promises";
import type { DatabaseSync } from "node:sqlite";
import { createGunzip } from "node:zlib";
import { AuthError, identityOrigin, mergeOpenApi, sendProblem, type Auth, type Role } from "@openasy/auth";
import type { Severity } from "./grype.ts";
import { missingHosts, type HostEntry, type HostsFileState } from "./hosts.ts";
import { log } from "./log.ts";
import { countRequest, renderMetrics } from "./metrics.ts";
import type { ProductLink } from "./products.ts";
import { AGENT_ID, SEVERITIES, VulnsError, parseLimit, type ProblemCode, type VulnFilter, type Vulns } from "./vulns.ts";

export interface AppOptions {
  db: DatabaseSync;
  vulns: Vulns;
  version: string;
  /** Sign-in, sessions, members and API tokens (ADR 0002, 0003). */
  auth: Auth;
  /**
   * Deprecated: one shared token with the admin role, for scripts written before sign-in existed. Use an API token
   * from Settings instead; this one has no expiry and is not tied to a person.
   */
  adminToken?: string;
  /** Token agents and CI send with SBOMs. It can add SBOMs and nothing else (ADR 0003). */
  ingestToken?: string;
  /** Where uploads are written before Grype reads them, on the data volume. */
  tmpDir: string;
  /** Built web UI; omit to run headless (ADR 0018). */
  webDir?: string;
  /** Built API reference (Swagger UI), served at /api/docs. */
  docsDir?: string;
  /** The OpenAPI description, served at /api/openapi.json with this release's version. */
  openapi?: Record<string, unknown>;
  /** false when /metrics is served on its own port instead (ADR 0026). */
  serveMetrics?: boolean;
  /** The install's OpenAsy products and their addresses, from OPENASY_PRODUCTS, for the product switcher. */
  products?: ProductLink[];
  /** The hosts file (OPENASY_HOSTS, ADR 0052) as last applied, and where it stands; absent when there is none. */
  hostsFile?: () => { state: HostsFileState; hosts: HostEntry[] };
}

function metricsText(vulns: Vulns, version: string) {
  const s = vulns.summary();
  return renderMetrics(version, {
    assets: s.assets,
    agents: vulns.countAgents(),
    findings: vulns.severityTotals(),
    knownExploited: s.knownExploited,
    feedBuilt: s.feed.built,
    queue: vulns.queueLength(),
  });
}

/** Serves only /metrics, for a port that is not exposed with the rest (VULNS_METRICS_PORT). */
export function createMetricsHandler(vulns: Vulns, version: string) {
  return (req: IncomingMessage, res: ServerResponse) => {
    if (new URL(req.url ?? "/", "http://localhost").pathname !== "/metrics") return problem(res, 404, "not-found");
    send(res, 200, metricsText(vulns, version), "text/plain; version=0.0.4");
  };
}

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".json": "application/json",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

// Identity keeps people's theme and language when they sign in through it; the pages read them there (ADR 0033).
const IDENTITY = identityOrigin(process.env);

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "content-security-policy": `default-src 'self'; connect-src 'self'${IDENTITY ? ` ${IDENTITY}` : ""}; img-src 'self' data:; style-src 'self' 'unsafe-inline'`,
};

/** Largest SBOM accepted, after decompression. A full host with language packages is a few tens of MB. */
const SBOM_LIMIT = 128 * 1024 * 1024;
/** Largest vulnerability data archive accepted for import. Today's archive is about 200 MB. */
const FEED_LIMIT = 1024 * 1024 * 1024;
/** How long `?wait=true` waits for a match before answering 202 anyway. */
const WAIT_MS = 120_000;

function send(res: ServerResponse, status: number, body: string | Buffer, type = "application/json", headers: Record<string, string> = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers, "content-type": type, "content-length": Buffer.byteLength(body) });
  res.end(body);
}

const json = (res: ServerResponse, status: number, data: unknown, headers?: Record<string, string>) =>
  send(res, status, JSON.stringify(data), "application/json", headers);

const TITLES: Record<ProblemCode, string> = {
  "invalid-token": "Invalid token",
  "invalid-json": "Invalid JSON",
  "invalid-body": "Invalid request body",
  "invalid-sbom": "Invalid SBOM",
  "version-mismatch": "Version mismatch",
  "not-found": "Not found",
  conflict: "Conflict",
  "not-configured": "Not configured",
  "payload-too-large": "Payload too large",
  "internal-error": "Internal error",
};

/** RFC 9457 Problem Details (ADR 0024). `code` is the stable part clients match on. */
function problem(res: ServerResponse, status: number, code: ProblemCode, detail?: string) {
  const body = { type: `https://openasy.github.io/problems/${code}`, title: TITLES[code], status, code, ...(detail && { detail }) };
  send(res, status, JSON.stringify(body), "application/problem+json");
}

/** Serves a file from dir, or returns false when the path is outside it or missing. */
async function serveFile(res: ServerResponse, dir: string, relative: string): Promise<boolean> {
  const file = normalize(join(dir, relative));
  if (!file.startsWith(normalize(dir)) || !extname(file)) return false;
  try {
    send(res, 200, await readFile(file), TYPES[extname(file)] ?? "application/octet-stream");
    return true;
  } catch {
    return false;
  }
}

/** Reads the whole body, gunzipping it when sent with `Content-Encoding: gzip`, up to limit bytes. */
async function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
  const encoding = req.headers["content-encoding"];
  if (encoding && encoding !== "gzip" && encoding !== "identity") throw new VulnsError(400, "invalid-body", "Content-Encoding must be gzip or absent.");
  const source = encoding === "gzip" ? req.pipe(createGunzip()) : req;
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of source as AsyncIterable<Buffer>) {
      size += chunk.length;
      if (size > limit) throw new VulnsError(413, "payload-too-large", `The body must be at most ${Math.round(limit / 1024 / 1024)} MiB.`);
      chunks.push(chunk);
    }
  } catch (err) {
    if (err instanceof VulnsError) throw err;
    throw new VulnsError(400, "invalid-body", "The gzip body could not be read.");
  }
  return Buffer.concat(chunks);
}

async function readJson(req: IncomingMessage, limit = 64 * 1024): Promise<Record<string, unknown>> {
  const raw = await readBody(req, limit).catch((err: unknown) => {
    if (err instanceof VulnsError && err.code === "payload-too-large")
      throw new VulnsError(400, "invalid-json", `The body must be JSON, at most ${Math.round(limit / 1024)} KiB.`);
    throw err;
  });
  try {
    const body = JSON.parse(raw.toString("utf8")) as unknown;
    if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error("not an object");
    return body as Record<string, unknown>;
  } catch {
    throw new VulnsError(400, "invalid-json", "The body must be a JSON object.");
  }
}

function tokenMatches(header: string | undefined, expected: string | undefined): boolean {
  if (!expected || !header?.startsWith("Bearer ")) return false;
  const a = Buffer.from(header.slice(7));
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** The role a route needs (ADR 0003), or "ingest" for SBOMs and heartbeats from vulns-agent and CI. */
type Access = "none" | "ingest" | Role;
interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  params: string[];
  body: () => Promise<Record<string, unknown>>;
}
interface Route {
  method: string;
  /** Path pattern; each `:name` matches one segment. */
  path: string;
  auth: Access;
  handle: (ctx: Ctx) => unknown;
}

const bool = (url: URL, name: string) => {
  const v = url.searchParams.get(name);
  if (v === null) return undefined;
  if (v !== "true" && v !== "false") throw new VulnsError(422, "invalid-body", `${name} must be true or false.`);
  return v === "true";
};

function vulnFilter(url: URL): VulnFilter {
  const status = url.searchParams.get("status") ?? "open";
  if (status !== "open" && status !== "excepted") throw new VulnsError(422, "invalid-body", "status must be open or excepted.");
  const severity = url.searchParams.get("severity")?.split(",").filter(Boolean) as Severity[] | undefined;
  if (severity?.some((s) => !SEVERITIES.includes(s)))
    throw new VulnsError(422, "invalid-body", `severity is a comma-separated list of ${SEVERITIES.join(", ")}.`);
  const kind = url.searchParams.get("kind");
  if (kind !== null && kind !== "host" && kind !== "image") throw new VulnsError(422, "invalid-body", "kind must be host or image.");
  const q = url.searchParams.get("q")?.trim();
  if (q && q.length > 128) throw new VulnsError(422, "invalid-body", "q must be at most 128 characters.");
  return {
    status,
    severity,
    kev: bool(url, "kev"),
    fixable: bool(url, "fixable"),
    kind: kind ?? undefined,
    assetId: url.searchParams.get("asset") ?? undefined,
    q: q || undefined,
  };
}

export function createApp({
  db,
  vulns,
  version,
  auth,
  adminToken,
  ingestToken,
  tmpDir,
  webDir,
  docsDir,
  openapi,
  serveMetrics = true,
  products = [],
  hostsFile,
}: AppOptions) {
  // The served description includes /api/v1/auth from @openasy/auth, so the API reference documents sign-in too.
  const spec = openapi && JSON.stringify({ ...mergeOpenApi(openapi), info: { ...(openapi.info as object), version } });
  const created = (res: ServerResponse, data: unknown) => (json(res, 201, data), undefined);
  const noContent = (res: ServerResponse) => {
    res.writeHead(204, SECURITY_HEADERS).end();
  };
  const cursor = (url: URL) => url.searchParams.get("cursor") ?? undefined;
  const limit = (url: URL) => parseLimit(url.searchParams.get("limit"));

  /** The servers in the hosts file this product has nothing for, with where the file stands (ADR 0052). */
  const coverage = () => {
    if (!hostsFile) return null;
    const { state, hosts } = hostsFile();
    return { ...state, missing: missingHosts(hosts, vulns.knownHosts()).map((h) => ({ name: h.name, address: h.address })) };
  };

  const routes: Route[] = [
    { method: "GET", path: "/api/v1/version", auth: "none", handle: () => ({ product: "vulns", version }) },
    { method: "GET", path: "/api/v1/products", auth: "viewer", handle: () => ({ products }) },
    { method: "GET", path: "/api/v1/summary", auth: "viewer", handle: () => ({ ...vulns.summary(), hostsFile: coverage() }) },
    { method: "GET", path: "/api/v1/overview", auth: "viewer", handle: () => vulns.overview() },

    // SBOMs in: from vulns-agent on hosts, and from CI for images.
    {
      method: "POST",
      path: "/api/v1/sboms",
      auth: "ingest",
      handle: async ({ req, res, url }) => {
        const raw = await readBody(req, SBOM_LIMIT);
        const { id, created: isNew, done } = vulns.ingest(url.searchParams.get("kind"), url.searchParams.get("name"), raw);
        if (bool(url, "wait")) {
          // CI can wait for the result and fail a build on it.
          const timer = new Promise<undefined>((resolve) => setTimeout(() => resolve(undefined), WAIT_MS).unref());
          const asset = await Promise.race([done, timer]);
          if (asset) return json(res, isNew ? 201 : 200, asset, { location: `/api/v1/assets/${id}` });
        } else {
          done.catch(() => {});
        }
        json(res, 202, vulns.asset(id), { location: `/api/v1/assets/${id}` });
      },
    },

    // Hosts and images.
    {
      method: "GET",
      path: "/api/v1/assets",
      auth: "viewer",
      handle: ({ url }) => {
        const page = vulns.listAssets(url.searchParams.get("kind"), cursor(url), limit(url));
        return { assets: page.items, ...(page.nextCursor && { nextCursor: page.nextCursor }) };
      },
    },
    { method: "GET", path: "/api/v1/assets/:id", auth: "viewer", handle: ({ params }) => vulns.asset(params[0]!) },
    { method: "DELETE", path: "/api/v1/assets/:id", auth: "admin", handle: ({ res, params }) => (vulns.deleteAsset(params[0]!), noContent(res)) },
    {
      method: "GET",
      path: "/api/v1/assets/:id/sbom",
      auth: "viewer",
      handle: ({ res, params }) => {
        const { body, format } = vulns.sbom(params[0]!);
        send(res, 200, body, "application/json", { "content-disposition": `attachment; filename="${params[0]}.${format}.json"`, "x-sbom-format": format });
      },
    },
    {
      method: "GET",
      path: "/api/v1/assets/:id/findings",
      auth: "viewer",
      handle: ({ url, params }) => {
        const status = url.searchParams.get("status") ?? "open";
        if (status !== "open" && status !== "excepted" && status !== "resolved")
          throw new VulnsError(422, "invalid-body", "status must be open, excepted or resolved.");
        const page = vulns.findings(params[0]!, status, cursor(url), limit(url));
        return { findings: page.items, ...(page.nextCursor && { nextCursor: page.nextCursor }) };
      },
    },
    {
      method: "POST",
      path: "/api/v1/assets/:id/scan",
      auth: "editor",
      handle: ({ res, params }) => (vulns.requestScan(params[0]!), json(res, 202, { status: "requested" })),
    },

    // Vulnerabilities across every asset.
    {
      method: "GET",
      path: "/api/v1/vulnerabilities",
      auth: "viewer",
      handle: ({ url }) => {
        const page = vulns.vulnerabilities(vulnFilter(url), cursor(url), limit(url));
        return { vulnerabilities: page.items, ...(page.nextCursor && { nextCursor: page.nextCursor }) };
      },
    },
    { method: "GET", path: "/api/v1/vulnerabilities/:id", auth: "viewer", handle: ({ params }) => vulns.vulnerability(params[0]!) },

    // Accepted risk.
    { method: "GET", path: "/api/v1/exceptions", auth: "viewer", handle: () => ({ exceptions: vulns.listExceptions() }) },
    { method: "POST", path: "/api/v1/exceptions", auth: "editor", handle: async ({ res, body }) => created(res, vulns.createException(await body())) },
    { method: "DELETE", path: "/api/v1/exceptions/:id", auth: "editor", handle: ({ res, params }) => (vulns.deleteException(params[0]!), noContent(res)) },

    // vulns-agent.
    {
      method: "POST",
      path: "/api/v1/agents/heartbeat",
      auth: "ingest",
      handle: async ({ res, body }) => {
        const { id, version: agentVersion, platform = "container", lastScanAt, lastError } = (await body()) as Record<string, unknown>;
        if (
          typeof id !== "string" ||
          !AGENT_ID.test(id) ||
          typeof agentVersion !== "string" ||
          (platform !== "container" && platform !== "kubernetes") ||
          (lastScanAt != null && (typeof lastScanAt !== "string" || Number.isNaN(Date.parse(lastScanAt)))) ||
          (lastError != null && (typeof lastError !== "string" || lastError.length > 1000))
        ) {
          throw new VulnsError(
            422,
            "invalid-body",
            "Expected { id, version, platform?, lastScanAt?, lastError? }; ids are lowercase host names, platform is container or kubernetes.",
          );
        }
        // ADR 0019: an agent always has the same version as its product.
        if (agentVersion !== version)
          throw new VulnsError(409, "version-mismatch", `vulns-agent ${agentVersion} does not match vulns ${version}; install vulns-agent ${version}`);
        const scanNow = vulns.heartbeat(
          id,
          agentVersion,
          platform,
          lastScanAt ? new Date(lastScanAt).toISOString() : null,
          (lastError as string | undefined) ?? null,
        );
        json(res, 202, { status: "accepted", scanNow });
      },
    },

    // Vulnerability data.
    { method: "GET", path: "/api/v1/feed", auth: "viewer", handle: () => vulns.feed() },
    {
      method: "POST",
      path: "/api/v1/feed/update",
      auth: "admin",
      handle: ({ res }) => {
        vulns.updateFeed().catch(() => {}); // the error is kept in the feed status
        json(res, 202, vulns.feed());
      },
    },
    {
      // Air-gapped installs (ADR 0015): download the archive elsewhere with `grype db download`, then upload it here.
      method: "PUT",
      path: "/api/v1/feed",
      auth: "admin",
      handle: async ({ req }) => {
        const length = Number(req.headers["content-length"] ?? 0);
        if (length > FEED_LIMIT) throw new VulnsError(413, "payload-too-large", "The archive must be at most 1 GiB.");
        await mkdir(tmpDir, { recursive: true });
        const file = join(tmpDir, `feed-${Date.now()}.tar.zst`);
        let size = 0;
        try {
          await pipeline(
            req,
            async function* (source: AsyncIterable<Buffer>) {
              for await (const chunk of source) {
                size += chunk.length;
                if (size > FEED_LIMIT) throw new VulnsError(413, "payload-too-large", "The archive must be at most 1 GiB.");
                yield chunk;
              }
            },
            createWriteStream(file, { mode: 0o600 }),
          );
          return await vulns.importFeed(file).catch((err: Error) => {
            throw new VulnsError(422, "invalid-body", `Grype could not import the archive: ${err.message}`);
          });
        } finally {
          await rm(file, { force: true });
        }
      },
    },
  ];

  const compiled = routes.map((r) => ({ ...r, re: new RegExp(`^${r.path.replace(/:[a-z]+/g, "([^/]+)")}$`) }));

  function authorize(req: IncomingMessage, access: Access) {
    if (access === "none") return;
    if (access === "ingest" && tokenMatches(req.headers.authorization, ingestToken)) return;
    if (tokenMatches(req.headers.authorization, adminToken)) return;
    if (access === "ingest") {
      // An API token or a session with the editor role can send SBOMs too, for CI set up from Settings.
      if (!ingestToken && !req.headers.authorization?.startsWith("Bearer oa_"))
        throw new VulnsError(503, "not-configured", "Set VULNS_INGEST_TOKEN on vulns, or send an API token with the editor role.");
      if (!req.headers.authorization?.startsWith("Bearer oa_"))
        throw new VulnsError(401, "invalid-token", "Send VULNS_INGEST_TOKEN or an API token as a bearer token.");
    }
    auth.authorize(req, access === "ingest" ? "editor" : access);
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<string> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;

    if (path === "/healthz") return (json(res, 200, { status: "ok" }), "/healthz");

    if (path === "/readyz") {
      // Ready to take SBOMs as long as the database answers. Missing vulnerability data is reported, not fatal:
      // SBOMs are kept and matched as soon as the data arrives.
      try {
        db.prepare("SELECT 1").get();
        const feed = vulns.feed();
        json(res, 200, { status: "ready", ...(!feed.built && { warnings: ["no vulnerability data yet: findings appear once it is downloaded or imported"] }) });
      } catch {
        json(res, 503, { status: "database unavailable" });
      }
      return "/readyz";
    }

    if (path === "/metrics") {
      // Not even the web UI's fallback answers here when metrics have their own port.
      if (serveMetrics) send(res, 200, metricsText(vulns, version), "text/plain; version=0.0.4");
      else problem(res, 404, "not-found");
      return "/metrics";
    }

    if (path === "/api/openapi.json" && spec) return (send(res, 200, spec), "/api/openapi.json");

    if (docsDir && (path === "/api/docs" || path.startsWith("/api/docs/"))) {
      if (path === "/api/docs") {
        res.writeHead(301, { ...SECURITY_HEADERS, location: "/api/docs/" }).end();
        return "/api/docs";
      }
      const relative = path.slice("/api/docs/".length) || "index.html";
      if (!(await serveFile(res, docsDir, relative))) problem(res, 404, "not-found");
      return "/api/docs";
    }

    if (await auth.handle(req, res)) return auth.routeName(req) ?? "/api/v1/auth/*";

    for (const r of compiled) {
      const m = path.match(r.re);
      if (!m || r.method !== req.method) continue;
      try {
        authorize(req, r.auth);
        const params = m.slice(1).map(decodeURIComponent);
        const result = await r.handle({ req, res, url, params, body: () => readJson(req) });
        if (!res.headersSent && result !== undefined) json(res, 200, result);
      } catch (err) {
        if (err instanceof AuthError) {
          sendProblem(res, err);
          if (!req.complete) req.resume();
          return r.path;
        }
        if (!(err instanceof VulnsError)) throw err;
        problem(res, err.status, err.code, err.message);
        // Unread request bodies would otherwise hold the connection.
        if (!req.complete) req.resume();
      }
      return r.path;
    }

    if (path.startsWith("/api/")) return (problem(res, 404, "not-found"), "/api/*");

    if (webDir && (req.method === "GET" || req.method === "HEAD")) {
      // Unknown paths fall back to the single-page app.
      if (!(await serveFile(res, webDir, path === "/" ? "index.html" : path))) send(res, 200, await readFile(join(webDir, "index.html")), TYPES[".html"]);
      return "/web";
    }

    problem(res, 404, "not-found");
    return "unmatched";
  }

  return async (req: IncomingMessage, res: ServerResponse) => {
    const started = performance.now();
    let routeName = "error";
    try {
      routeName = await route(req, res);
    } catch (err) {
      log("error", "request failed", { error: String(err), path: req.url });
      if (!res.headersSent) problem(res, 500, "internal-error");
    }
    countRequest(req.method ?? "GET", routeName, res.statusCode);
    if (routeName !== "/healthz" && routeName !== "/metrics") {
      log("info", "request", { method: req.method, path: url(req), status: res.statusCode, ms: Math.round(performance.now() - started) });
    }
  };
}

/** The path without the query string, which may name hosts and images. */
const url = (req: IncomingMessage) => (req.url ?? "/").split("?")[0];
