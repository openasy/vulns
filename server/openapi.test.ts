import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ADMIN_TOKEN, ALL_PACKAGES, INGEST_TOKEN, sbom, startApp } from "./test-app.ts";

// Contract tests (ADR 0024): every response the API sends must match openapi.json.

type Spec = {
  info: { version: string };
  paths: Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, { schema: object }> }> }>>;
  components: { responses: Record<string, { content: Record<string, { schema: object }> }> };
};

const spec = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Spec;
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");

const docsDir = mkdtempSync(join(tmpdir(), "vulns-docs-"));
writeFileSync(join(docsDir, "index.html"), "<!doctype html><title>API</title>");

let app: Awaited<ReturnType<typeof startApp>>;
let base: string;
const covered = new Set<string>();

beforeAll(async () => {
  app = await startApp({ version, openapi: spec, docsDir });
  base = app.base;
});

afterAll(() => app.close());

/** Calls the API and checks status, content type and body against the description. */
async function call(method: string, path: string, init: RequestInit = {}, concrete = path) {
  const res = await fetch(base + concrete, { ...init, method });
  const operation = spec.paths[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not in openapi.json`).toBeDefined();
  covered.add(`${method} ${path}`);

  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which openapi.json does not list`).toBeDefined();
  // A response is either inline or a $ref to components/responses; build the JSON pointer to its schema either way.
  const shared = declared!.$ref?.split("/").pop();
  const response = shared ? spec.components.responses[shared]! : declared!;
  const at = shared ? `openapi#/components/responses/${shared}` : `openapi#/paths/${path.replaceAll("/", "~1")}/${method.toLowerCase()}/responses/${res.status}`;

  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { res, body: undefined };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect(response.content?.[type], `${method} ${path} ${res.status} sent ${type}, which openapi.json does not list`).toBeDefined();

  const body = type.endsWith("json") ? await res.json() : await res.text();
  const schema = `${at}/content/${type.replace("/", "~1")}/schema`;
  const validate = ajv.getSchema(schema)!;
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
  return { res, body };
}

const auth = (token: string, body?: string, type = "application/json") => ({ headers: { authorization: `Bearer ${token}`, "content-type": type }, ...(body !== undefined && { body }) });
const admin = (body?: unknown) => auth(ADMIN_TOKEN, body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body));
const ingest = (body?: string) => auth(INGEST_TOKEN, body);
const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();

describe("openapi.json", () => {
  it("has the version of this release", () => {
    expect(spec.info.version).toBe(version);
  });

  it("is served with the running version", async () => {
    const served = (await (await fetch(`${base}/api/openapi.json`)).json()) as Spec;
    expect(served.info.version).toBe(version);
    expect(Object.keys(served.paths)).toEqual(Object.keys(spec.paths));
  });

  it("serves the API reference at /api/docs/", async () => {
    expect((await fetch(`${base}/api/docs`, { redirect: "manual" })).headers.get("location")).toBe("/api/docs/");
    const res = await fetch(`${base}/api/docs/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect((await fetch(`${base}/api/docs/../../package.json`)).status).not.toBe(200);
  });
});

describe("responses match openapi.json", () => {
  let host = "";
  let image = "";

  it("product and health", async () => {
    await call("GET", "/api/v1/version");
    await call("GET", "/healthz");
    await call("GET", "/readyz");
    await call("GET", "/metrics");
  });

  it("SBOMs: matched, queued, and every refusal", async () => {
    host = ((await call("POST", "/api/v1/sboms", ingest(sbom(...ALL_PACKAGES)), "/api/v1/sboms?kind=host&name=web-1&wait=true")).body as { id: string }).id;
    await call("POST", "/api/v1/sboms", ingest(sbom(...ALL_PACKAGES)), "/api/v1/sboms?kind=host&name=web-1&wait=true");
    image = ((await call("POST", "/api/v1/sboms", ingest(sbom("perl-base")), "/api/v1/sboms?kind=image&name=ghcr.io/acme/app:1.4.2")).body as { id: string }).id;
    await app.vulns.enqueue(async () => {});
    await call("POST", "/api/v1/sboms", ingest("{not json"), "/api/v1/sboms?kind=image&name=app");
    await call("POST", "/api/v1/sboms", ingest(JSON.stringify({ hello: 1 })), "/api/v1/sboms?kind=image&name=app");
    await call("POST", "/api/v1/sboms", ingest(sbom()), "/api/v1/sboms?kind=vm&name=app");
    await call("POST", "/api/v1/sboms", auth("wrong", sbom()), "/api/v1/sboms?kind=image&name=app");
  });

  it("vulnerabilities", async () => {
    const { body } = await call("GET", "/api/v1/vulnerabilities", admin());
    expect((body as { vulnerabilities: unknown[] }).vulnerabilities).toHaveLength(4);
    await call("GET", "/api/v1/vulnerabilities", admin(), "/api/v1/vulnerabilities?severity=high,critical&kev=true&fixable=true&kind=host&q=libc&limit=1");
    await call("GET", "/api/v1/vulnerabilities", admin(), "/api/v1/vulnerabilities?limit=2");
    await call("GET", "/api/v1/vulnerabilities", admin(), "/api/v1/vulnerabilities?severity=urgent");
    await call("GET", "/api/v1/vulnerabilities", {});
    await call("GET", "/api/v1/vulnerabilities/{id}", admin(), "/api/v1/vulnerabilities/CVE-2023-4911");
    await call("GET", "/api/v1/vulnerabilities/{id}", admin(), "/api/v1/vulnerabilities/CVE-1999-0001");
    await call("GET", "/api/v1/summary", admin());
    await call("GET", "/api/v1/summary", {});
  });

  it("assets", async () => {
    await call("GET", "/api/v1/assets", admin());
    await call("GET", "/api/v1/assets", admin(), "/api/v1/assets?kind=image&limit=1");
    await call("GET", "/api/v1/assets", admin(), "/api/v1/assets?kind=vm");
    await call("GET", "/api/v1/assets/{id}", admin(), `/api/v1/assets/${host}`);
    await call("GET", "/api/v1/assets/{id}", admin(), "/api/v1/assets/missing");
    await call("GET", "/api/v1/assets/{id}/findings", admin(), `/api/v1/assets/${host}/findings`);
    await call("GET", "/api/v1/assets/{id}/findings", admin(), `/api/v1/assets/${host}/findings?status=resolved`);
    await call("GET", "/api/v1/assets/{id}/findings", admin(), `/api/v1/assets/${host}/findings?status=gone`);
    await call("GET", "/api/v1/assets/{id}/findings", admin(), "/api/v1/assets/missing/findings");
    await call("GET", "/api/v1/assets/{id}/sbom", admin(), `/api/v1/assets/${image}/sbom`);
    await call("GET", "/api/v1/assets/{id}/sbom", admin(), "/api/v1/assets/missing/sbom");
    await call("POST", "/api/v1/assets/{id}/scan", admin(), `/api/v1/assets/${image}/scan`);
    await call("POST", "/api/v1/assets/{id}/scan", admin(), "/api/v1/assets/missing/scan");
    await call("DELETE", "/api/v1/assets/{id}", admin(), `/api/v1/assets/${image}`);
    await call("DELETE", "/api/v1/assets/{id}", admin(), "/api/v1/assets/missing");
    await call("GET", "/api/v1/assets", {});
  });

  it("agents", async () => {
    await call("POST", "/api/v1/agents/heartbeat", ingest(JSON.stringify({ id: "web-1", version, lastScanAt: new Date().toISOString() })));
    await call("POST", "/api/v1/assets/{id}/scan", admin(), `/api/v1/assets/${host}/scan`);
    const { body } = await call("POST", "/api/v1/agents/heartbeat", ingest(JSON.stringify({ id: "web-1", version })));
    expect(body).toEqual({ status: "accepted", scanNow: true });
    await call("POST", "/api/v1/agents/heartbeat", ingest(JSON.stringify({ id: "web-1", version: "0.0.1" })));
    await call("POST", "/api/v1/agents/heartbeat", ingest(JSON.stringify({ id: "Web 1", version })));
    await call("POST", "/api/v1/agents/heartbeat", ingest("{nope"));
    await call("POST", "/api/v1/agents/heartbeat", auth("wrong", "{}"));
    await call("GET", "/api/v1/assets/{id}", admin(), `/api/v1/assets/${host}`);
  });

  it("exceptions", async () => {
    const ex = (await call("POST", "/api/v1/exceptions", admin({ vulnerability: "CVE-2023-4911", assetId: host, reason: "No setuid binaries", expiresAt: inDays(30) }))).body as { id: string };
    await call("POST", "/api/v1/exceptions", admin({ vulnerability: "CVE-2023-6780", reason: "Accepted for every asset", expiresAt: inDays(90) }));
    await call("POST", "/api/v1/exceptions", admin({ vulnerability: "CVE-2023-6780", reason: "x", expiresAt: inDays(90) }));
    await call("POST", "/api/v1/exceptions", admin("nope"));
    await call("GET", "/api/v1/exceptions", admin());
    await call("GET", "/api/v1/vulnerabilities", admin(), "/api/v1/vulnerabilities?status=excepted");
    await call("GET", "/api/v1/assets/{id}/findings", admin(), `/api/v1/assets/${host}/findings?status=excepted`);
    await call("DELETE", "/api/v1/exceptions/{id}", admin(), `/api/v1/exceptions/${ex.id}`);
    await call("DELETE", "/api/v1/exceptions/{id}", admin(), "/api/v1/exceptions/missing");
    for (const [m, p] of [["GET", "/api/v1/exceptions"], ["POST", "/api/v1/exceptions"]] as const) await call(m, p, { method: m });
  });

  it("vulnerability data", async () => {
    await call("GET", "/api/v1/feed", admin());
    await call("POST", "/api/v1/feed/update", admin());
    await app.vulns.enqueue(async () => {});
    await call("PUT", "/api/v1/feed", auth(ADMIN_TOKEN, "archive", "application/zstd"));
    app.matcher.import = async () => {
      throw new Error("not a grype database archive");
    };
    await call("PUT", "/api/v1/feed", auth(ADMIN_TOKEN, "garbage", "application/zstd"));
    await call("GET", "/api/v1/feed", {});
    await call("POST", "/api/v1/feed/update", {});
    await call("PUT", "/api/v1/feed", {});
  });

  it("refuses everything when tokens are not configured", async () => {
    const closed = await startApp({ version, openapi: spec, adminToken: undefined, ingestToken: undefined });
    const was = base;
    base = closed.base;
    await call("GET", "/api/v1/summary", admin());
    await call("POST", "/api/v1/sboms", ingest(sbom()), "/api/v1/sboms?kind=image&name=app");
    await call("POST", "/api/v1/agents/heartbeat", ingest(JSON.stringify({ id: "web-1", version })));
    await call("GET", "/api/v1/vulnerabilities/{id}", admin(), "/api/v1/vulnerabilities/CVE-2023-4911");
    for (const [m, p] of [
      ["GET", "/api/v1/assets"],
      ["GET", "/api/v1/assets/{id}"],
      ["DELETE", "/api/v1/assets/{id}"],
      ["GET", "/api/v1/assets/{id}/findings"],
      ["GET", "/api/v1/assets/{id}/sbom"],
      ["POST", "/api/v1/assets/{id}/scan"],
      ["DELETE", "/api/v1/exceptions/{id}"],
    ] as const) {
      await call(m, p, { method: m }, p.replace("{id}", "x"));
    }
    base = was;
    await closed.close();
  });

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});
