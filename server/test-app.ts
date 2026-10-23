// Starts the app on a random port for tests, with a stand-in for Grype.
import { mkdtempSync, readFileSync } from "node:fs";
import { createServer, type RequestListener, type Server } from "node:http";
import { createAuth } from "@openasy/auth";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createApp, type AppOptions } from "./app.ts";
import { openDb } from "./db.ts";
import { parseReport, type FeedStatus, type Matcher } from "./grype.ts";
import { createVulns } from "./vulns.ts";

export const INGEST_TOKEN = "test-ingest-token";
export const ADMIN_TOKEN = "test-admin-token";

/** Real `grype -o json` output for debian:12.0, cut down to four matches. */
export const FIXTURE = JSON.parse(readFileSync(new URL("./fixtures/grype-debian-12.json", import.meta.url), "utf8")) as {
  matches: Array<{ artifact: { name: string } }>;
};

/** A Syft SBOM listing these packages. */
export const sbom = (...packages: string[]) =>
  JSON.stringify({
    descriptor: { name: "syft" },
    schema: { version: "16.0.0" },
    distro: { prettyName: "Debian GNU/Linux 12 (bookworm)" },
    artifacts: packages.map((name) => ({ name })),
  });
export const ALL_PACKAGES = [...new Set(FIXTURE.matches.map((m) => m.artifact.name))];

/** Matches the packages an SBOM lists against the fixture, so dropping a package resolves its findings. */
export function fakeMatcher(feed: FeedStatus | null = { schema: "v6.1.10", built: new Date().toISOString() }) {
  const calls = { match: 0, update: 0, import: [] as string[] };
  let current = feed;
  const matcher: Matcher & { calls: typeof calls; setFeed: (f: FeedStatus | null) => void; fail?: string } = {
    calls,
    setFeed: (f) => (current = f),
    async match(raw) {
      calls.match++;
      if (matcher.fail) throw new Error(matcher.fail);
      const names = new Set((JSON.parse(raw.toString("utf8")) as { artifacts?: Array<{ name: string }> }).artifacts?.map((a) => a.name));
      return parseReport({ ...FIXTURE, matches: FIXTURE.matches.filter((m) => names.has(m.artifact.name)) });
    },
    async status() {
      return current;
    },
    async update() {
      calls.update++;
      const next = { schema: "v6.1.10", built: new Date(Date.now() + 1000).toISOString() };
      const changed = next.built !== current?.built;
      current = next;
      return changed;
    },
    async import(archive) {
      calls.import.push(readFileSync(archive, "utf8"));
      current = { schema: "v6.1.10", built: "2026-10-01T00:00:00Z" };
    },
  };
  return matcher;
}

export async function startApp(opts: Partial<AppOptions> & { version: string; matcher?: ReturnType<typeof fakeMatcher> }) {
  const db = openDb(":memory:");
  const matcher = opts.matcher ?? fakeMatcher();
  const vulns = createVulns(db, matcher);
  await vulns.refreshFeed();
  const tmpDir = mkdtempSync(join(tmpdir(), "vulns-tmp-"));
  // The origin is known once the port is, so the handler is set after listening.
  let handler: RequestListener = (_req, res) => res.writeHead(503).end();
  const server: Server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const auth = createAuth({ db, product: "vulns", productName: "OpenAsy Vulnerabilities", origin: base });
  handler = createApp({ db, vulns, auth, ingestToken: INGEST_TOKEN, adminToken: ADMIN_TOKEN, tmpDir, ...opts });
  const admin = (path: string, init: RequestInit = {}) =>
    fetch(base + path, { ...init, headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json", ...init.headers } });
  const ingest = (path: string, init: RequestInit = {}) =>
    fetch(base + path, { ...init, headers: { authorization: `Bearer ${INGEST_TOKEN}`, "content-type": "application/json", ...init.headers } });
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return { db, vulns, matcher, auth, base, admin, ingest, close };
}
