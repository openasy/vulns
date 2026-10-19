// Prometheus text exposition, written by hand: a few lines, no client library needed.
const requests = new Map<string, number>();

export function countRequest(method: string, route: string, status: number) {
  const key = `method="${method}",route="${route}",status="${status}"`;
  requests.set(key, (requests.get(key) ?? 0) + 1);
}

export interface Gauges {
  assets: { hosts: number; images: number; failed: number };
  agents: number;
  /** Open findings (one per vulnerability, package and asset) by severity. */
  findings: Record<string, number>;
  knownExploited: number;
  feedBuilt: string | null;
  queue: number;
}

export function renderMetrics(version: string, g: Gauges): string {
  const lines = [
    "# HELP openasy_build_info Build information.",
    "# TYPE openasy_build_info gauge",
    `openasy_build_info{product="vulns",version="${version}"} 1`,
    "# HELP openasy_http_requests_total HTTP requests handled.",
    "# TYPE openasy_http_requests_total counter",
    ...[...requests].map(([labels, n]) => `openasy_http_requests_total{${labels}} ${n}`),
    "# HELP openasy_vulns_assets Hosts and images with an SBOM.",
    "# TYPE openasy_vulns_assets gauge",
    `openasy_vulns_assets{kind="host"} ${g.assets.hosts}`,
    `openasy_vulns_assets{kind="image"} ${g.assets.images}`,
    "# HELP openasy_vulns_assets_failed Assets whose last match failed.",
    "# TYPE openasy_vulns_assets_failed gauge",
    `openasy_vulns_assets_failed ${g.assets.failed}`,
    "# HELP openasy_vulns_agents Known vulns-agent instances.",
    "# TYPE openasy_vulns_agents gauge",
    `openasy_vulns_agents ${g.agents}`,
    "# HELP openasy_vulns_open_findings Open findings by severity, without accepted exceptions.",
    "# TYPE openasy_vulns_open_findings gauge",
    ...Object.entries(g.findings).map(([s, n]) => `openasy_vulns_open_findings{severity="${s}"} ${n}`),
    "# HELP openasy_vulns_known_exploited Open vulnerabilities in the CISA KEV catalogue.",
    "# TYPE openasy_vulns_known_exploited gauge",
    `openasy_vulns_known_exploited ${g.knownExploited}`,
    "# HELP openasy_vulns_feed_built_timestamp_seconds When the vulnerability data in use was built; 0 when there is none.",
    "# TYPE openasy_vulns_feed_built_timestamp_seconds gauge",
    `openasy_vulns_feed_built_timestamp_seconds ${g.feedBuilt ? Math.floor(Date.parse(g.feedBuilt) / 1000) : 0}`,
    "# HELP openasy_vulns_queue Matches and updates waiting to run.",
    "# TYPE openasy_vulns_queue gauge",
    `openasy_vulns_queue ${g.queue}`,
    "# HELP process_uptime_seconds Seconds since the process started.",
    "# TYPE process_uptime_seconds gauge",
    `process_uptime_seconds ${process.uptime().toFixed(0)}`,
  ];
  return lines.join("\n") + "\n";
}
