import { chmodSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createGrype } from "./grype.ts";

const fixture = readFileSync(new URL("./fixtures/grype-debian-12.json", import.meta.url), "utf8");

/** A stand-in grype that records its arguments and environment, and answers like the real one. */
function fakeGrype(dir: string, exit = 0) {
  const bin = join(dir, "grype");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
const fs = require("fs");
const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(join(dir, "calls.jsonl"))}, JSON.stringify({ args, env: Object.fromEntries(Object.entries(process.env).filter(([k]) => k.startsWith("GRYPE_"))),
  sbom: args[0]?.startsWith("sbom:") ? fs.readFileSync(args[0].slice(5), "utf8") : null }) + "\\n");
if (${exit}) { process.stderr.write("1 error occurred:\\n\\t* boom\\n"); process.exit(${exit}); }
if (args[0] === "db" && args[1] === "status") process.stdout.write(JSON.stringify({ schemaVersion: "v6.1.10", built: "2026-10-19T06:39:15Z", valid: true }));
else if (args[0]?.startsWith("sbom:")) process.stdout.write(fs.readFileSync(${JSON.stringify(join(dir, "fixture.json"))}, "utf8"));
`,
  );
  chmodSync(bin, 0o755);
  writeFileSync(join(dir, "fixture.json"), fixture);
  const calls = () =>
    readFileSync(join(dir, "calls.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as { args: string[]; env: Record<string, string>; sbom: string | null });
  return { bin, calls };
}

describe("createGrype", () => {
  it("matches an SBOM from a file it removes afterwards, with updates and phone-home off", async () => {
    const dir = mkdtempSync(join(tmpdir(), "grype-"));
    const tmp = mkdtempSync(join(tmpdir(), "grype-tmp-"));
    const { bin, calls } = fakeGrype(dir);
    const grype = createGrype({ bin, dataDir: join(dir, "data"), tmpDir: tmp });

    const report = await grype.match(Buffer.from('{"artifacts":[]}'));
    expect(report.matches.map((m) => m.vulnId)).toContain("CVE-2023-4911");
    const [call] = calls();
    expect(call!.args.slice(1)).toEqual(["-o", "json", "-q"]);
    expect(call!.sbom).toBe('{"artifacts":[]}');
    expect(call!.env).toMatchObject({ GRYPE_DB_AUTO_UPDATE: "false", GRYPE_CHECK_FOR_APP_UPDATE: "false", GRYPE_DB_CACHE_DIR: join(dir, "data") });
    expect(readdirSync(tmp)).toEqual([]);
  });

  it("reads the data status and passes a mirror URL", async () => {
    const dir = mkdtempSync(join(tmpdir(), "grype-"));
    const { bin, calls } = fakeGrype(dir);
    const grype = createGrype({ bin, dataDir: dir, tmpDir: dir, updateUrl: "https://mirror.example.com/databases" });
    expect(await grype.status()).toEqual({ schema: "v6.1.10", built: "2026-10-19T06:39:15Z" });
    expect(calls()[0]!.env.GRYPE_DB_UPDATE_URL).toBe("https://mirror.example.com/databases");
  });

  it("reports Grype's last error line and still removes the SBOM", async () => {
    const dir = mkdtempSync(join(tmpdir(), "grype-"));
    const tmp = mkdtempSync(join(tmpdir(), "grype-tmp-"));
    const { bin } = fakeGrype(dir, 1);
    const grype = createGrype({ bin, dataDir: dir, tmpDir: tmp });
    await expect(grype.match(Buffer.from("{}"))).rejects.toThrow("grype match failed (exit 1): * boom");
    await expect(grype.import("/tmp/x.tar.zst")).rejects.toThrow("grype db import failed");
    expect(await grype.status()).toBeNull();
    expect(readdirSync(tmp)).toEqual([]);
  });
});
