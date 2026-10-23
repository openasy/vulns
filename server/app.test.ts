import { createHmac } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FIXTURE, INGEST_TOKEN, ALL_PACKAGES, fakeMatcher, sbom, startApp } from "./test-app.ts";
import { createMetricsHandler } from "./app.ts";
import { parseReport } from "./grype.ts";
import { inspectSbom } from "./vulns.ts";

let app: Awaited<ReturnType<typeof startApp>>;

beforeEach(async () => {
  app = await startApp({ version: "1.2.3" });
});
afterEach(() => app.close());

const upload = (kind: string, name: string, body: string, opts: { wait?: boolean; token?: string; gzip?: boolean } = {}) =>
  fetch(`${app.base}/api/v1/sboms?kind=${kind}&name=${encodeURIComponent(name)}${opts.wait === false ? "" : "&wait=true"}`, {
    method: "POST",
    headers: { authorization: `Bearer ${opts.token ?? INGEST_TOKEN}`, "content-type": "application/json", ...(opts.gzip && { "content-encoding": "gzip" }) },
    body: opts.gzip ? gzipSync(body) : body,
  });

const get = async <T>(path: string) => (await (await app.admin(path)).json()) as T;
type Vuln = {
  vulnerability: string;
  severity: string;
  knownExploited: boolean;
  hosts: number;
  images: number;
  fix: { state: string; version: string | null };
  package: { name: string; versions: string[] };
};

describe("parseReport", () => {
  it("keeps what ranks a finding: severity, CVSS, EPSS, KEV, risk and the fix", () => {
    const { distro, matches } = parseReport(FIXTURE);
    expect(distro).toBe("debian 12.0");
    const kev = matches.find((m) => m.vulnId === "CVE-2023-4911")!;
    expect(kev).toMatchObject({
      pkgName: "libc-bin",
      pkgVersion: "2.36-9",
      pkgType: "deb",
      severity: "high",
      cvss: 7.8,
      kev: true,
      kevDue: "2023-12-12",
      fixState: "fixed",
      fixedVersion: "2.36-9+deb12u3",
    });
    expect(kev.epss).toBeGreaterThan(0.5);
    expect(kev.risk).toBeGreaterThan(50);
    expect(matches.find((m) => m.vulnId === "CVE-2025-13151")).toMatchObject({ fixState: "wont-fix", fixedVersion: null, kev: false });
  });

  it("drops malformed matches and refuses output that is not Grype's", () => {
    expect(parseReport({ matches: [{ vulnerability: { id: "CVE-1" } }, null, { artifact: { name: "x" } }] }).matches).toEqual([]);
    expect(() => parseReport({ nope: 1 })).toThrow(/no matches/);
  });
});

describe("inspectSbom", () => {
  it("reads Syft, CycloneDX and SPDX", () => {
    expect(inspectSbom(JSON.parse(sbom("a", "b")))).toEqual({ format: "syft-json", packages: 2, distro: "Debian GNU/Linux 12 (bookworm)" });
    expect(inspectSbom({ bomFormat: "CycloneDX", components: [{ type: "operating-system", name: "alpine", version: "3.22" }, { type: "library" }] })).toEqual({
      format: "cyclonedx-json",
      packages: 1,
      distro: "alpine 3.22",
    });
    expect(inspectSbom({ spdxVersion: "SPDX-2.3", packages: [{}, {}, {}] })).toEqual({ format: "spdx-json", packages: 3, distro: null });
    expect(() => inspectSbom({ hello: "world" })).toThrow(/Syft JSON, CycloneDX JSON or SPDX JSON/);
  });
});

describe("health and metrics", () => {
  it("answers liveness, readiness and version", async () => {
    expect((await fetch(`${app.base}/healthz`)).status).toBe(200);
    expect(await (await fetch(`${app.base}/readyz`)).json()).toEqual({ status: "ready" });
    const res = await fetch(`${app.base}/api/v1/version`);
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(await res.json()).toEqual({ product: "vulns", version: "1.2.3" });
  });

  it("warns in readiness while there is no vulnerability data", async () => {
    const empty = await startApp({ version: "1.2.3", matcher: fakeMatcher(null) });
    const body = (await (await fetch(`${empty.base}/readyz`)).json()) as { status: string; warnings: string[] };
    expect(body.status).toBe("ready");
    expect(body.warnings[0]).toMatch(/no vulnerability data/);
    await empty.close();
  });

  it("exposes Prometheus metrics", async () => {
    await upload("host", "web-1", sbom(...ALL_PACKAGES));
    const text = await (await fetch(`${app.base}/metrics`)).text();
    expect(text).toContain('openasy_build_info{product="vulns",version="1.2.3"} 1');
    expect(text).toContain('openasy_vulns_assets{kind="host"} 1');
    expect(text).toContain('openasy_vulns_open_findings{severity="high"} 3');
    expect(text).toContain("openasy_vulns_known_exploited 1");
  });
});

describe("metrics on their own port", () => {
  it("keeps /metrics off the main port and serves only /metrics on the other", async () => {
    const webDir = mkdtempSync(join(tmpdir(), "vulns-web-"));
    writeFileSync(join(webDir, "index.html"), "<!doctype html>");
    const split = await startApp({ version: "1.2.3", serveMetrics: false, webDir });
    expect((await fetch(`${split.base}/metrics`)).status).toBe(404);
    const server = createServer(createMetricsHandler(split.vulns, "1.2.3"));
    await new Promise<void>((r) => server.listen(0, r));
    const port = (server.address() as AddressInfo).port;
    expect(await (await fetch(`http://localhost:${port}/metrics`)).text()).toContain('openasy_build_info{product="vulns",version="1.2.3"} 1');
    expect((await fetch(`http://localhost:${port}/api/v1/assets`)).status).toBe(404);
    await new Promise((r) => server.close(r));
    await split.close();
  });
});

describe("tokens", () => {
  it("refuses management calls without sign-in, and the ingest token is not enough", async () => {
    const anonymous = await fetch(`${app.base}/api/v1/assets`);
    expect(anonymous.status).toBe(401);
    expect(await anonymous.json()).toMatchObject({ code: "unauthenticated" });
    expect((await app.ingest("/api/v1/assets")).status).toBe(401);
  });

  it("accepts SBOMs with the ingest token or the deprecated admin token", async () => {
    expect((await upload("image", "app:1", sbom("perl-base"), { token: "nope" })).status).toBe(401);
    expect((await upload("image", "app:1", sbom("perl-base"))).status).toBe(201);
    expect((await upload("image", "app:2", sbom("perl-base"), { token: "test-admin-token" })).status).toBe(201);
  });

  it("says which variable to set when the ingest token is missing", async () => {
    const open = await startApp({ version: "1.2.3", ingestToken: undefined, adminToken: undefined });
    const res = await fetch(`${open.base}/api/v1/sboms?kind=image&name=x`, { method: "POST", body: sbom() });
    expect(res.status).toBe(503);
    expect(((await res.json()) as { detail: string }).detail).toContain("VULNS_INGEST_TOKEN");
    await open.close();
  });
});

/** A browser: keeps cookies and sends the Origin header of the page. */
function browser(base: string) {
  const jar = new Map<string, string>();
  return async (path: string, init: { method?: string; body?: unknown; origin?: string } = {}) => {
    const res = await fetch(base + path, {
      method: init.method ?? (init.body === undefined ? "GET" : "POST"),
      headers: {
        origin: init.origin ?? base,
        cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; "),
        ...(init.body !== undefined && { "content-type": "application/json" }),
      },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(";");
      const i = pair!.indexOf("=");
      jar.set(pair!.slice(0, i), pair!.slice(i + 1));
    }
    return res;
  };
}

/** The current RFC 6238 code for a base32 secret. */
function totpNow(secret: string) {
  const bits = [...secret].map((c) => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(c).toString(2).padStart(5, "0")).join("");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const mac = createHmac("sha1", key).update(counter).digest();
  return String((mac.readUInt32BE(mac[19]! & 15) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

describe("sign-in and roles", () => {
  const PASSWORD = "correct horse battery staple";

  async function owner() {
    const b = browser(app.base);
    const token = new URL(app.auth.setupLink()!).searchParams.get("setup");
    expect((await b("/api/v1/auth/setup", { body: { token, name: "Olivia", email: "owner@example.com", password: PASSWORD } })).status).toBe(200);
    return b;
  }

  async function member(admin: ReturnType<typeof browser>, email: string, role: string) {
    const { link } = (await (await admin("/api/v1/auth/members", { body: { email, role } })).json()) as { link: string };
    const b = browser(app.base);
    expect((await b(`/api/v1/auth/links/${new URL(link).searchParams.get("link")}`, { body: { password: PASSWORD } })).status).toBe(200);
    return b;
  }

  it("makes the owner set up a second factor before anything else", async () => {
    const b = await owner();
    const res = await b("/api/v1/summary");
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ code: "mfa-setup-required" });
    const { secret } = (await (await b("/api/v1/auth/me/totp", { body: {} })).json()) as { secret: string };
    expect((await b("/api/v1/auth/me/totp/confirm", { body: { code: totpNow(secret) } })).status).toBe(200);
    expect((await b("/api/v1/summary")).status).toBe(200);
  });

  it("gives viewers, editors and admins what their role allows", async () => {
    const o = await owner();
    const { secret } = (await (await o("/api/v1/auth/me/totp", { body: {} })).json()) as { secret: string };
    await o("/api/v1/auth/me/totp/confirm", { body: { code: totpNow(secret) } });
    await upload("host", "web-1", sbom(...ALL_PACKAGES));
    const assetId = (await get<{ assets: Array<{ id: string }> }>("/api/v1/assets")).assets[0]!.id;
    const exception = { vulnerability: "CVE-2023-4911", reason: "not reachable", expiresAt: new Date(Date.now() + 86_400_000).toISOString() };

    const viewer = await member(o, "vic@example.com", "viewer");
    expect((await viewer("/api/v1/vulnerabilities")).status).toBe(200);
    expect((await viewer(`/api/v1/assets/${assetId}/sbom`)).status).toBe(200);
    expect((await viewer("/api/v1/exceptions", { body: exception })).status).toBe(403);
    expect((await viewer(`/api/v1/assets/${assetId}/scan`, { body: {} })).status).toBe(403);

    const editor = await member(o, "ed@example.com", "editor");
    expect((await editor("/api/v1/exceptions", { body: exception })).status).toBe(201);
    expect((await editor(`/api/v1/assets/${assetId}`, { method: "DELETE" })).status).toBe(403);
    expect((await editor("/api/v1/feed/update", { body: {} })).status).toBe(403);

    expect((await o(`/api/v1/assets/${assetId}`, { method: "DELETE" })).status).toBe(204);
  });

  it("refuses changes sent from another site with the session cookie", async () => {
    const o = await owner();
    const { secret } = (await (await o("/api/v1/auth/me/totp", { body: {} })).json()) as { secret: string };
    await o("/api/v1/auth/me/totp/confirm", { body: { code: totpNow(secret) } });
    const res = await o("/api/v1/feed/update", { body: {}, origin: "https://evil.example" });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ code: "cross-site" });
  });

  it("lets CI send SBOMs with an API token that has the editor role", async () => {
    const o = await owner();
    const { secret } = (await (await o("/api/v1/auth/me/totp", { body: {} })).json()) as { secret: string };
    await o("/api/v1/auth/me/totp/confirm", { body: { code: totpNow(secret) } });
    const make = async (role: string) => ((await (await o("/api/v1/auth/tokens", { body: { name: `ci-${role}`, role } })).json()) as { token: string }).token;
    expect((await upload("image", "app:ci", sbom("perl-base"), { token: await make("editor") })).status).toBe(201);
    expect((await upload("image", "app:ci2", sbom("perl-base"), { token: await make("viewer") })).status).toBe(403);
  });
});

describe("SBOMs and findings", () => {
  it("matches an SBOM and ranks known exploited vulnerabilities first", async () => {
    const res = await upload("host", "web-1", sbom(...ALL_PACKAGES));
    expect(res.status).toBe(201);
    const asset = (await res.json()) as {
      id: string;
      kind: string;
      distro: string;
      packages: number;
      match: { status: string };
      open: Record<string, number>;
      knownExploited: number;
      fixable: number;
    };
    expect(asset).toMatchObject({
      kind: "host",
      distro: "debian 12.0",
      packages: ALL_PACKAGES.length,
      match: { status: "done" },
      knownExploited: 1,
      fixable: 2,
    });
    expect(asset.open).toMatchObject({ high: 3, medium: 1 });

    const { vulnerabilities } = await get<{ vulnerabilities: Vuln[] }>("/api/v1/vulnerabilities");
    expect(vulnerabilities[0]).toMatchObject({
      vulnerability: "CVE-2023-4911",
      knownExploited: true,
      hosts: 1,
      images: 0,
      fix: { state: "fixed", version: "2.36-9+deb12u3" },
    });
    expect(vulnerabilities).toHaveLength(4);
  });

  it("accepts gzip and answers 202 without waiting", async () => {
    const res = await upload("image", "ghcr.io/openasy/app:1.0.0", sbom("perl-base"), { gzip: true, wait: false });
    expect(res.status).toBe(202);
    const { id } = (await res.json()) as { id: string };
    await app.vulns.enqueue(async () => {});
    expect((await get<{ match: { status: string } }>(`/api/v1/assets/${id}`)).match.status).toBe("done");
  });

  it("groups one vulnerability across hosts and images", async () => {
    await upload("host", "web-1", sbom("libc-bin"));
    await upload("host", "web-2", sbom("libc-bin"));
    await upload("image", "app:1", sbom("libc-bin"));
    const { vulnerabilities } = await get<{ vulnerabilities: Vuln[] }>("/api/v1/vulnerabilities?kev=true");
    expect(vulnerabilities).toEqual([
      expect.objectContaining({
        vulnerability: "CVE-2023-4911",
        hosts: 2,
        images: 1,
        package: { name: "glibc", type: "deb", packages: ["libc-bin"], versions: ["2.36-9"] },
      }),
    ]);

    const detail = await get<{ affected: Array<{ asset: { name: string } }> }>("/api/v1/vulnerabilities/CVE-2023-4911");
    expect(detail.affected.map((a) => a.asset.name)).toEqual(["web-1", "web-2", "app:1"]);
  });

  it("filters by severity, fix, kind and text", async () => {
    await upload("host", "web-1", sbom(...ALL_PACKAGES));
    await upload("image", "app:1", sbom("perl-base"));
    const ids = async (q: string) =>
      (await get<{ vulnerabilities: Vuln[] }>(`/api/v1/vulnerabilities?${q}`)).vulnerabilities.map((v) => v.vulnerability).sort();
    expect(await ids("severity=medium")).toEqual(["CVE-2023-6780"]);
    expect(await ids("fixable=true")).toEqual(["CVE-2023-4911", "CVE-2023-6780"]);
    expect(await ids("kind=image")).toEqual(["CVE-2026-82560"]);
    expect(await ids("q=libtasn")).toEqual(["CVE-2025-13151"]);
    expect((await app.admin("/api/v1/vulnerabilities?severity=urgent")).status).toBe(422);
  });

  it("pages with an opaque cursor", async () => {
    await upload("host", "web-1", sbom(...ALL_PACKAGES));
    const first = await get<{ vulnerabilities: Vuln[]; nextCursor: string }>("/api/v1/vulnerabilities?limit=3");
    expect(first.vulnerabilities).toHaveLength(3);
    const second = await get<{ vulnerabilities: Vuln[]; nextCursor?: string }>(`/api/v1/vulnerabilities?limit=3&cursor=${first.nextCursor}`);
    expect(second.vulnerabilities).toHaveLength(1);
    expect(second.nextCursor).toBeUndefined();
    expect((await app.admin("/api/v1/vulnerabilities?cursor=garbage")).status).toBe(422);
  });

  it("resolves findings that no longer match, and keeps them as history", async () => {
    const { id } = (await (await upload("host", "web-1", sbom(...ALL_PACKAGES))).json()) as { id: string };
    // libc-bin was upgraded: its two findings are resolved.
    const again = await upload("host", "web-1", sbom("perl-base", "libtasn1-6"));
    expect(again.status).toBe(200);
    expect(((await again.json()) as { id: string }).id).toBe(id);
    const open = await get<{ findings: Array<{ vulnerability: string }> }>(`/api/v1/assets/${id}/findings`);
    expect(open.findings.map((f) => f.vulnerability).sort()).toEqual(["CVE-2025-13151", "CVE-2026-82560"]);
    const resolved = await get<{ findings: Array<{ vulnerability: string; resolvedAt: string }> }>(`/api/v1/assets/${id}/findings?status=resolved`);
    expect(resolved.findings.map((f) => f.vulnerability).sort()).toEqual(["CVE-2023-4911", "CVE-2023-6780"]);
    expect(resolved.findings[0]!.resolvedAt).toBeTruthy();
  });

  it("keeps the SBOM for export and deletes everything with the asset", async () => {
    const body = sbom("perl-base");
    const { id } = (await (await upload("image", "app:1", body)).json()) as { id: string };
    const res = await app.admin(`/api/v1/assets/${id}/sbom`);
    expect(res.headers.get("x-sbom-format")).toBe("syft-json");
    expect(await res.text()).toBe(body);
    expect((await app.admin(`/api/v1/assets/${id}`, { method: "DELETE" })).status).toBe(204);
    expect((await app.admin(`/api/v1/assets/${id}`)).status).toBe(404);
    expect((await get<{ vulnerabilities: Vuln[] }>("/api/v1/vulnerabilities")).vulnerabilities).toEqual([]);
  });

  it("refuses what is not an SBOM, with Problem Details", async () => {
    const res = await upload("image", "app:1", JSON.stringify({ hello: "world" }));
    expect(res.status).toBe(422);
    expect(res.headers.get("content-type")).toBe("application/problem+json");
    expect(await res.json()).toMatchObject({ code: "invalid-sbom" });
    expect((await upload("image", "app:1", "not json")).status).toBe(400);
    expect((await upload("vm", "app:1", sbom())).status).toBe(422);
    expect((await upload("image", "bad name with spaces", sbom())).status).toBe(422);
  });

  it("stops reading a gzip body past the limit", async () => {
    const bomb = gzipSync(Buffer.alloc(129 * 1024 * 1024, 32));
    const res = await fetch(`${app.base}/api/v1/sboms?kind=image&name=app:1`, {
      method: "POST",
      headers: { authorization: `Bearer ${INGEST_TOKEN}`, "content-type": "application/json", "content-encoding": "gzip" },
      body: bomb,
    });
    expect(res.status).toBe(413);
    expect(await res.json()).toMatchObject({ code: "payload-too-large" });
  });

  it("records a failed match on the asset", async () => {
    app.matcher.fail = "grype match failed (exit 1): boom";
    const asset = (await (await upload("image", "app:1", sbom("perl-base"))).json()) as { match: { status: string; error: string } };
    expect(asset.match).toMatchObject({ status: "failed", error: "grype match failed (exit 1): boom" });
  });

  it("keeps SBOMs until vulnerability data exists, then matches them", async () => {
    const matcher = fakeMatcher(null);
    const late = await startApp({ version: "1.2.3", matcher });
    const res = await fetch(`${late.base}/api/v1/sboms?kind=host&name=web-1&wait=true`, {
      method: "POST",
      headers: { authorization: `Bearer ${INGEST_TOKEN}` },
      body: sbom(...ALL_PACKAGES),
    });
    expect(((await res.json()) as { match: { status: string; error: string } }).match).toMatchObject({
      status: "queued",
      error: expect.stringContaining("Waiting for vulnerability data"),
    });
    await late.vulns.updateFeed();
    await late.vulns.enqueue(async () => {});
    await new Promise((r) => setTimeout(r, 10));
    await late.vulns.enqueue(async () => {});
    const summary = (await (await late.admin("/api/v1/summary")).json()) as { knownExploited: number; feed: { built: string } };
    expect(summary.knownExploited).toBe(1);
    expect(summary.feed.built).toBeTruthy();
    await late.close();
  });
});

describe("exceptions", () => {
  const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();

  it("hides a vulnerability on one asset until it expires", async () => {
    const web1 = (await (await upload("host", "web-1", sbom("libc-bin"))).json()) as { id: string };
    await upload("host", "web-2", sbom("libc-bin"));
    const res = await app.admin("/api/v1/exceptions", {
      method: "POST",
      body: JSON.stringify({ vulnerability: "CVE-2023-4911", assetId: web1.id, reason: "No setuid binaries on this host", expiresAt: inDays(30) }),
    });
    expect(res.status).toBe(201);
    const ex = (await res.json()) as { id: string; active: boolean; asset: { name: string } };
    expect(ex).toMatchObject({ active: true, asset: { name: "web-1" } });

    const open = await get<{ vulnerabilities: Vuln[] }>("/api/v1/vulnerabilities?q=CVE-2023-4911");
    expect(open.vulnerabilities[0]).toMatchObject({ hosts: 1 });
    const excepted = await get<{ vulnerabilities: Vuln[] }>("/api/v1/vulnerabilities?status=excepted");
    expect(excepted.vulnerabilities).toEqual([expect.objectContaining({ vulnerability: "CVE-2023-4911", hosts: 1 })]);
    expect((await get<{ knownExploited: number }>(`/api/v1/assets/${web1.id}`)).knownExploited).toBe(0);

    expect((await app.admin(`/api/v1/exceptions/${ex.id}`, { method: "DELETE" })).status).toBe(204);
    expect((await get<{ vulnerabilities: Vuln[] }>("/api/v1/vulnerabilities?q=CVE-2023-4911")).vulnerabilities[0]).toMatchObject({ hosts: 2 });
  });

  it("needs a reason and an expiry within a year", async () => {
    const post = (body: unknown) => app.admin("/api/v1/exceptions", { method: "POST", body: JSON.stringify(body) });
    expect((await post({ vulnerability: "CVE-2023-4911", reason: "ok", expiresAt: inDays(30) })).status).toBe(422);
    expect((await post({ vulnerability: "CVE-2023-4911", reason: "Accepted by security", expiresAt: inDays(400) })).status).toBe(422);
    expect((await post({ vulnerability: "CVE-2023-4911", reason: "Accepted by security", expiresAt: inDays(-1) })).status).toBe(422);
    expect((await post({ vulnerability: "x", reason: "Accepted by security", expiresAt: inDays(30) })).status).toBe(422);
    expect((await post({ vulnerability: "CVE-2023-4911", assetId: "missing", reason: "Accepted by security", expiresAt: inDays(30) })).status).toBe(422);
    expect((await post({ vulnerability: "CVE-2023-4911", reason: "Accepted by security", expiresAt: inDays(30) })).status).toBe(201);
  });
});

describe("agents", () => {
  const beat = (body: unknown, token = INGEST_TOKEN) =>
    fetch(`${app.base}/api/v1/agents/heartbeat`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify(body),
    });

  it("refuses an agent of another version", async () => {
    const res = await beat({ id: "web-1", version: "1.1.0" });
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ code: "version-mismatch", detail: expect.stringContaining("install vulns-agent 1.2.3") });
  });

  it("validates the body", async () => {
    expect((await beat({ id: "Web 1", version: "1.2.3" })).status).toBe(422);
    expect((await beat({ id: "web-1", version: "1.2.3", lastScanAt: "yesterday" })).status).toBe(422);
    expect((await beat({ id: "web-1", version: "1.2.3", platform: "vm" })).status).toBe(422);
  });

  it("shows the agent on its host and passes on a scan request once", async () => {
    expect(await (await beat({ id: "web-1", version: "1.2.3" })).json()).toEqual({ status: "accepted", scanNow: false });
    const { id } = (await (await upload("host", "web-1", sbom("perl-base"))).json()) as { id: string };
    await beat({ id: "web-1", version: "1.2.3", platform: "kubernetes", lastScanAt: new Date().toISOString() });
    const host = await get<{ agent: { version: string; lastSeen: string } }>(`/api/v1/assets/${id}`);
    expect(host.agent).toMatchObject({ version: "1.2.3", platform: "kubernetes" });

    expect((await app.admin(`/api/v1/assets/${id}/scan`, { method: "POST" })).status).toBe(202);
    expect(((await (await beat({ id: "web-1", version: "1.2.3" })).json()) as { scanNow: boolean }).scanNow).toBe(true);
    expect(((await (await beat({ id: "web-1", version: "1.2.3" })).json()) as { scanNow: boolean }).scanNow).toBe(false);
  });

  it("cannot ask an image or a host without an agent to scan", async () => {
    const image = (await (await upload("image", "app:1", sbom())).json()) as { id: string };
    expect((await app.admin(`/api/v1/assets/${image.id}/scan`, { method: "POST" })).status).toBe(409);
    const host = (await (await upload("host", "db-1", sbom())).json()) as { id: string };
    expect((await app.admin(`/api/v1/assets/${host.id}/scan`, { method: "POST" })).status).toBe(409);
  });
});

describe("vulnerability data", () => {
  it("updates on request and matches every asset again", async () => {
    await upload("host", "web-1", sbom(...ALL_PACKAGES));
    const before = app.matcher.calls.match;
    expect((await app.admin("/api/v1/feed/update", { method: "POST" })).status).toBe(202);
    await app.vulns.enqueue(async () => {});
    await new Promise((r) => setTimeout(r, 10));
    await app.vulns.enqueue(async () => {});
    expect(app.matcher.calls.update).toBe(1);
    expect(app.matcher.calls.match).toBe(before + 1);
    expect(await get<{ checkedAt: string; error: null }>("/api/v1/feed")).toMatchObject({ checkedAt: expect.any(String), error: null });
  });

  it("imports an archive for air-gapped installs", async () => {
    const res = await app.admin("/api/v1/feed", { method: "PUT", headers: { "content-type": "application/zstd" }, body: "archive-bytes" });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ built: "2026-10-01T00:00:00Z" });
    expect(app.matcher.calls.import).toEqual(["archive-bytes"]);
  });
});

describe("other products", () => {
  it("lists the configured products to anyone signed in", async () => {
    const products = [{ id: "infrastructure", url: "https://infra.example.com" }];
    const linked = await startApp({ version: "1.2.3", products });
    expect(await (await linked.admin("/api/v1/products")).json()).toEqual({ products });
    expect((await fetch(`${linked.base}/api/v1/products`)).status).toBe(401);
    await linked.close();
  });
});
