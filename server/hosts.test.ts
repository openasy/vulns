import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseHosts } from "./hosts.ts";
import { startApp } from "./test-app.ts";

// The same file as in Infrastructure and Logs (ADR 0052).
const FIXTURE = readFileSync(new URL("./testdata/hosts.yaml", import.meta.url), "utf8");
const json = async (res: Response) => (await res.json()) as any;

describe("servers in the hosts file", () => {
  it("are listed when this product has nothing for them, by host assets", async () => {
    const hosts = parseHosts(FIXTURE);
    const state = { path: "/config/hosts.yaml", appliedAt: "2026-10-01T00:00:00.000Z", entries: hosts.length, error: null, warnings: [] };
    const app = await startApp({ version: "0.1.0", hostsFile: () => ({ state, hosts }) });
    const add = (kind: string, name: string) => {
      const id = randomUUID();
      const at = new Date().toISOString();
      app.db
        .prepare("INSERT INTO assets (id, kind, name, sbom, sbom_format, sbom_at, match_status, created_at) VALUES (?, ?, ?, ?, 'cyclonedx', ?, 'done', ?)")
        .run(id, kind, name, Buffer.from("{}"), at, at);
    };
    try {
      const summary = async () => (await json(await app.admin("/api/v1/summary"))).hostsFile;
      expect(await summary()).toEqual({
        ...state,
        missing: [
          { name: "bastion", address: "10.0.0.2" },
          { name: "web-1", address: "10.0.0.5" },
          { name: "db-1", address: "10.0.0.6" },
        ],
      });
      // By full name and by address; an image named db-1 is not a server.
      add("host", "web-1.example.com");
      add("host", "10.0.0.2");
      add("image", "db-1");
      expect((await summary()).missing).toEqual([{ name: "db-1", address: "10.0.0.6" }]);
    } finally {
      await app.close();
    }
  });

  it("are not looked for without a file", async () => {
    const app = await startApp({ version: "0.1.0" });
    try {
      expect((await json(await app.admin("/api/v1/summary"))).hostsFile).toBeNull();
    } finally {
      await app.close();
    }
  });
});
