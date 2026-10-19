import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Forward-only migrations (ADR 0010): append new entries, never edit or remove old ones.
const MIGRATIONS = [
  `CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
   -- A host (reported by vulns-agent) or a container image (sent from CI). The SBOM is kept so every asset can be
   -- matched again when the vulnerability data changes, without scanning it again.
   CREATE TABLE assets (
     id TEXT PRIMARY KEY,
     kind TEXT NOT NULL CHECK (kind IN ('host', 'image')),
     name TEXT NOT NULL,
     distro TEXT,
     packages INTEGER NOT NULL DEFAULT 0,
     sbom BLOB NOT NULL,
     sbom_format TEXT NOT NULL,
     sbom_at TEXT NOT NULL,
     match_status TEXT NOT NULL CHECK (match_status IN ('queued', 'matching', 'done', 'failed')),
     match_error TEXT,
     matched_at TEXT,
     scan_requested INTEGER NOT NULL DEFAULT 0,
     created_at TEXT NOT NULL,
     UNIQUE (kind, name)
   );
   -- One row per vulnerability in one package version on one asset. Rows that stop matching get resolved_at;
   -- they open again if the same package version matches again.
   CREATE TABLE findings (
     asset_id TEXT NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
     vuln_id TEXT NOT NULL,
     pkg_name TEXT NOT NULL,
     pkg_version TEXT NOT NULL,
     pkg_type TEXT NOT NULL,
     pkg_source TEXT NOT NULL,
     purl TEXT,
     location TEXT,
     severity TEXT NOT NULL,
     cvss REAL,
     epss REAL,
     epss_percentile REAL,
     kev INTEGER NOT NULL DEFAULT 0,
     kev_due TEXT,
     ransomware INTEGER NOT NULL DEFAULT 0,
     risk REAL NOT NULL DEFAULT 0,
     fix_state TEXT NOT NULL,
     fixed_version TEXT,
     description TEXT,
     data_source TEXT,
     aliases TEXT NOT NULL DEFAULT '[]',
     first_seen TEXT NOT NULL,
     last_seen TEXT NOT NULL,
     resolved_at TEXT,
     PRIMARY KEY (asset_id, vuln_id, pkg_name, pkg_version, pkg_type)
   );
   CREATE INDEX findings_open ON findings (vuln_id, pkg_source) WHERE resolved_at IS NULL;
   -- Accepted risk: hides a vulnerability on one asset or on all of them until it expires.
   CREATE TABLE exceptions (
     id TEXT PRIMARY KEY,
     vuln_id TEXT NOT NULL,
     asset_id TEXT REFERENCES assets (id) ON DELETE CASCADE,
     reason TEXT NOT NULL,
     created_at TEXT NOT NULL,
     expires_at TEXT NOT NULL
   );
   CREATE INDEX exceptions_vuln ON exceptions (vuln_id);
   -- vulns-agent instances, by host name. Their SBOMs become host assets of the same name.
   CREATE TABLE agents (
     id TEXT PRIMARY KEY,
     version TEXT NOT NULL,
     platform TEXT NOT NULL DEFAULT 'container',
     last_seen TEXT NOT NULL,
     last_scan_at TEXT,
     last_error TEXT
   )`,
];

/** Opens the product's single SQLite file in WAL mode (ADR 0011) and migrates it forward. */
export function openDb(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
  const row = db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").get() as { v: number };
  for (let v = row.v; v < MIGRATIONS.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(MIGRATIONS[v]!);
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(v + 1, new Date().toISOString());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }
  return db;
}
