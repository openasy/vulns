// What the search window (Cmd+K) finds in Vulnerabilities: open vulnerabilities by id, alias or package, from the
// API, and hosts and images by name.
import type { SearchFn, SearchResult } from "@openasy/ui";
import { Container, Server, ShieldAlert } from "lucide-react";
import type { Asset, Severity, Vulnerability } from "./api.ts";
import type { T } from "./i18n.ts";

type Call = <R>(path: string, init?: RequestInit) => Promise<R>;

// Grype's "negligible" and "unknown" have no level of their own in the shared scale.
const level = (s: Severity) => (s === "negligible" || s === "unknown" ? "info" : s);

export function search(call: Call, t: T): SearchFn {
  return async (q, signal) => {
    const [found, assets] = await Promise.all([
      call<{ vulnerabilities: Vulnerability[] }>(`/api/v1/vulnerabilities?${new URLSearchParams({ q, limit: "8" })}`, { signal }),
      call<{ assets: Asset[] }>("/api/v1/assets?limit=500", { signal }),
    ]);
    const vulnerabilities: SearchResult[] = found.vulnerabilities.map((v) => ({
      id: `vulnerability:${v.vulnerability}:${v.package.name}`,
      label: v.vulnerability,
      detail: t("search.vulnerabilityDetail", { package: v.package.name, versions: v.package.versions.join(", "), hosts: v.hosts, images: v.images }),
      kind: t("search.vulnerability"),
      icon: ShieldAlert,
      severity: level(v.severity),
      mono: true,
      href: `/findings?q=${encodeURIComponent(v.vulnerability)}`,
    }));
    const named: SearchResult[] = assets.assets
      .filter((a) => a.name.toLowerCase().includes(q))
      .slice(0, 6)
      .map((a) => ({
        id: `asset:${a.id}`,
        label: a.name,
        detail: t("search.assetDetail", { distro: a.distro ?? "–", open: Object.values(a.open).reduce((n, c) => n + c, 0) }),
        kind: a.kind === "host" ? t("search.host") : t("search.image"),
        icon: a.kind === "host" ? Server : Container,
        mono: a.kind === "image",
        href: `/assets/${encodeURIComponent(a.id)}`,
      }));
    return [...vulnerabilities, ...named];
  };
}
