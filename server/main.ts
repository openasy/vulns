import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { createApp, createMetricsHandler } from "./app.ts";
import { openDb } from "./db.ts";
import { createGrype } from "./grype.ts";
import { log } from "./log.ts";
import { createVulns } from "./vulns.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const port = Number(process.env.PORT ?? 8080);
const dbPath = process.env.VULNS_DB ?? "/data/vulns.db";
const feedDir = process.env.VULNS_FEED_DIR ?? "/data/grype";
const tmpDir = process.env.TMPDIR ?? "/data/tmp";
const updateHours = Number(process.env.VULNS_FEED_UPDATE_HOURS ?? 24);
const retentionDays = Number(process.env.VULNS_RETENTION_DAYS ?? 90);
const webDir = new URL("../dist/web", import.meta.url).pathname;
const docsDir = new URL("../dist/docs", import.meta.url).pathname;
const openapi = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Record<string, unknown>;
const headless = process.env.VULNS_HEADLESS === "true";
// Set it to keep /metrics off the port that is published or behind an ingress (ADR 0026).
const metricsPort = process.env.VULNS_METRICS_PORT ? Number(process.env.VULNS_METRICS_PORT) : undefined;

if (!Number.isFinite(updateHours) || updateHours < 0) throw new Error("VULNS_FEED_UPDATE_HOURS must be 0 (off) or a number of hours");
mkdirSync(feedDir, { recursive: true });
mkdirSync(tmpDir, { recursive: true });

const db = openDb(dbPath);
const grype = createGrype({ bin: process.env.VULNS_GRYPE_BIN ?? "/usr/local/bin/grype", dataDir: feedDir, tmpDir, updateUrl: process.env.VULNS_FEED_URL });
const vulns = createVulns(db, grype, { retentionDays });
const server = createServer(
  createApp({
    db,
    vulns,
    version,
    adminToken: process.env.VULNS_ADMIN_TOKEN,
    ingestToken: process.env.VULNS_INGEST_TOKEN,
    tmpDir,
    webDir: !headless && existsSync(webDir) ? webDir : undefined,
    docsDir: existsSync(docsDir) ? docsDir : undefined,
    openapi,
    serveMetrics: metricsPort === undefined,
  }),
);
const metricsServer = metricsPort !== undefined ? createServer(createMetricsHandler(vulns, version)) : undefined;
metricsServer?.listen(metricsPort, () => log("info", "metrics on their own port", { port: metricsPort }));

server.listen(port, () => log("info", "vulns started", { version, port, db: dbPath, feed: feedDir, headless, feedUpdateHours: updateHours }));
if (!process.env.VULNS_ADMIN_TOKEN) log("warn", "VULNS_ADMIN_TOKEN is not set; the management API and UI will refuse every request");
if (!process.env.VULNS_INGEST_TOKEN) log("warn", "VULNS_INGEST_TOKEN is not set; vulns-agent and CI can send SBOMs only with the admin token");
// Until sign-in exists (ADR 0002), this release is for test environments only.
log("warn", "the management API uses one shared token: use this release only for testing");

const feed = await vulns.refreshFeed();
log("info", feed ? "vulnerability data found" : "no vulnerability data yet", { built: feed?.built, schema: feed?.schema, path: join(feedDir, "6") });
// Assets that were waiting when the product stopped.
void vulns.rematchAll();

const timers: NodeJS.Timeout[] = [];
if (updateHours > 0) {
  // Downloads only vulnerability data, from grype.anchore.io or VULNS_FEED_URL. Nothing about this install is sent (ADR 0015).
  const update = () => vulns.updateFeed().catch(() => {});
  void update();
  timers.push(setInterval(update, updateHours * 3_600_000));
} else {
  log("info", "automatic updates are off; import vulnerability data with PUT /api/v1/feed");
}
vulns.purge();
timers.push(setInterval(() => vulns.purge(), 24 * 3_600_000));

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  for (const t of timers) clearInterval(t);
  metricsServer?.close();
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
