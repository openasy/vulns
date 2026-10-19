import {
  AppShell,
  Badge,
  BrandProvider,
  Button,
  Callout,
  DataTable,
  EmptyState,
  EntityChip,
  FacetFilter,
  FilterBar,
  IconButton,
  KpiCard,
  KpiGrid,
  PageHeader,
  Panel,
  SearchInput,
  SegmentedControl,
  SelectField,
  SeverityBadge,
  StatusBadge,
  Switch,
  Tabs,
  TextField,
  type Column,
  type Severity as UiSeverity,
} from "@openasy/ui";
import { Boxes, Download, Play, RefreshCw, Server, Settings2, ShieldOff, Trash2, TriangleAlert, X } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  readToken,
  saveToken,
  Unauthorized,
  type Asset,
  type Counts,
  type Exception,
  type Feed,
  type Finding,
  type Kind,
  type Severity,
  type Summary,
  type Vulnerability,
  type VulnerabilityDetail,
} from "./api.ts";

// Grype's "negligible" and "unknown" have no level of their own in the shared scale.
const ui = (s: Severity): UiSeverity => (s === "negligible" || s === "unknown" ? "info" : s);
const pct = (v: number | null) => (v === null ? "–" : `${(v * 100).toFixed(1)}%`);

function ago(iso: string | null | undefined): string {
  if (!iso) return "never";
  const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86_400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86_400)} d ago`;
}

type Route = { page: "findings" | "hosts" | "images" | "exceptions" | "setup" } | { page: "asset"; id: string };
function parseRoute(hash: string): Route {
  const [page, id] = hash.replace(/^#\/?/, "").split("/");
  if (page === "assets" && id) return { page: "asset", id: decodeURIComponent(id) };
  if (page === "hosts" || page === "images" || page === "exceptions" || page === "setup") return { page };
  return { page: "findings" };
}
const go = (hash: string) => (window.location.hash = hash);

/** Data loading with the token; an expired or wrong token sends the user back to the token form. */
function useApi(token: string, onUnauthorized: (msg?: string) => void) {
  return useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      try {
        return await api<T>(path, token, init);
      } catch (err) {
        if (err instanceof Unauthorized) onUnauthorized(err.message);
        throw err;
      }
    },
    [token, onUnauthorized],
  );
}
type Call = ReturnType<typeof useApi>;

function TokenForm({ error, onToken }: { error?: string; onToken: (t: string) => void }) {
  const [value, setValue] = useState("");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    onToken(value.trim());
  };
  return (
    <Panel title="Admin token">
      <form onSubmit={submit} className="flex max-w-md flex-col gap-3">
        <p className="m-0 text-sm text-fg-muted">Sign-in is not built yet. Paste the VULNS_ADMIN_TOKEN set on vulns; it is kept only in this tab.</p>
        <TextField label="VULNS_ADMIN_TOKEN" type="password" autoComplete="off" mono value={value} onChange={(e) => setValue(e.target.value)} error={error} />
        <div>
          <Button type="submit" variant="primary" disabled={!value.trim()}>
            Continue
          </Button>
        </div>
      </form>
    </Panel>
  );
}

const SEV4 = ["critical", "high", "medium", "low"] as const;

/** Compact severity counts; each badge carries the full name for screen readers. */
function SevCounts({ counts }: { counts: Counts }) {
  const label = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
  const tone = { critical: "critical", high: "danger", medium: "warning", low: "info" } as const;
  return (
    <span className="flex flex-wrap gap-1">
      {SEV4.map((s) => (
        <Badge key={s} tone={counts[s] ? tone[s] : "neutral"} mono className="min-w-8 justify-center">
          <span aria-hidden>{label[s][0]}</span>
          <span className="sr-only">{label[s]}</span> {counts[s]}
        </Badge>
      ))}
    </span>
  );
}

function FixCell({ fix, versions }: { fix: Vulnerability["fix"]; versions: string }) {
  return (
    <span className="flex min-w-0 flex-col font-mono text-xs">
      <span className="vulns-wrap text-fg-muted">
        {versions} →{" "}
        {fix.version ? <span className="text-success">{fix.version}</span> : fix.state === "wont-fix" ? "won't fix" : "no fix yet"}
      </span>
    </span>
  );
}

function NoFeed({ feed }: { feed: Feed | undefined }) {
  if (!feed || feed.built) {
    if (feed?.ageHours != null && feed.ageHours > 72) {
      return (
        <Callout tone="warning" title={`Vulnerability data is ${Math.round(feed.ageHours / 24)} days old`}>
          New vulnerabilities are missing until it is updated. {feed.error ? `Last update failed: ${feed.error}` : ""} See <a href="#/setup">Setup</a>.
        </Callout>
      );
    }
    return null;
  }
  return (
    <Callout tone="info" title={feed.updating ? "Downloading vulnerability data" : "No vulnerability data yet"}>
      {feed.updating
        ? "The first download is about 200 MB and takes a few minutes. SBOMs sent meanwhile are kept and matched as soon as it finishes."
        : feed.error
          ? `The download failed: ${feed.error}. Import it instead, see Setup.`
          : "Download or import it from Setup; SBOMs are kept until then."}
    </Callout>
  );
}

// ---------------------------------------------------------------- Findings

const plural = (n: number, one: string) => `${n} ${one}${n === 1 ? "" : "s"}`;
const affected = (v: Vulnerability) => [v.hosts && plural(v.hosts, "host"), v.images && plural(v.images, "image")].filter(Boolean).join(" · ");
const rowId = (v: Vulnerability) => `${v.vulnerability}|${v.package.type}|${v.package.name}`;

type Tab = "open" | "excepted";

function VulnPanel({ id, call, onClose, onChanged }: { id: string; call: Call; onClose: () => void; onChanged: () => void }) {
  const [detail, setDetail] = useState<VulnerabilityDetail>();
  const [days, setDays] = useState("90");
  const [reason, setReason] = useState("");
  const [scope, setScope] = useState("all");
  const [error, setError] = useState<string>();

  useEffect(() => {
    setDetail(undefined);
    call<VulnerabilityDetail>(`/api/v1/vulnerabilities/${encodeURIComponent(id)}`).then(setDetail, () => setDetail(undefined));
  }, [id, call]);

  const accept = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await call("/api/v1/exceptions", {
        method: "POST",
        body: JSON.stringify({ vulnerability: id, reason, expiresAt: new Date(Date.now() + Number(days) * 86_400_000).toISOString(), ...(scope !== "all" && { assetId: scope }) }),
      });
      setReason("");
      setError(undefined);
      onChanged();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <Panel
      aria-label={`${id} details`}
      title={id}
      description={detail?.aliases.length ? `Also ${detail.aliases.join(", ")}` : undefined}
      actions={
        <IconButton label="Close details" size="sm" onClick={onClose}>
          <X />
        </IconButton>
      }
    >
      {!detail ? (
        <p className="text-sm text-fg-muted">Loading…</p>
      ) : (
        <div className="flex flex-col gap-3 text-sm">
          <div className="flex flex-wrap items-center gap-1.5">
            <SeverityBadge severity={ui(detail.severity)} />
            {detail.cvss !== null && <Badge mono>CVSS {detail.cvss.toFixed(1)}</Badge>}
            <Badge mono>EPSS {pct(detail.epss)}</Badge>
            {detail.knownExploited && <StatusBadge tone="danger">In CISA KEV{detail.kevDueDate ? `, due ${detail.kevDueDate}` : ""}</StatusBadge>}
            {detail.ransomware && <Badge tone="critical">Used by ransomware</Badge>}
          </div>
          {detail.description && <p className="m-0 text-fg-muted">{detail.description}</p>}
          {detail.dataSource && (
            <a href={detail.dataSource} target="_blank" rel="noreferrer noopener" className="text-xs">
              Advisory
            </a>
          )}
          <div className="flex flex-col gap-1">
            <span className="text-2xs font-medium tracking-wider text-fg-muted uppercase">Where</span>
            <ul className="vulns-list flex flex-col gap-1">
              {detail.affected.map((a) => (
                <li key={`${a.asset.id}-${a.package.name}-${a.package.version}`} className="flex flex-wrap items-center gap-1.5 text-xs">
                  <EntityChip kind={a.asset.kind === "host" ? "host" : "container"} value={a.asset.name} href={`#/assets/${a.asset.id}`} />
                  <span className="font-mono">
                    {a.package.name} {a.package.version} → {a.fix.version ?? "no fix"}
                  </span>
                  {a.excepted && <Badge>Accepted</Badge>}
                </li>
              ))}
            </ul>
          </div>
          <form onSubmit={accept} className="flex flex-col gap-2 border-t border-line pt-3">
            <span className="text-2xs font-medium tracking-wider text-fg-muted uppercase">Accept the risk</span>
            <TextField label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} hint="Why it is acceptable, for the next review." error={error} />
            <div className="grid grid-cols-2 gap-2">
              <SelectField
                label="On"
                value={scope}
                onChange={(e) => setScope(e.target.value)}
                options={[{ value: "all", label: "Every asset" }, ...[...new Map(detail.affected.map((a) => [a.asset.id, a.asset.name]))].map(([value, label]) => ({ value, label }))]}
              />
              <SelectField
                label="For"
                value={days}
                onChange={(e) => setDays(e.target.value)}
                options={[
                  { value: "30", label: "30 days" },
                  { value: "90", label: "90 days" },
                  { value: "180", label: "180 days" },
                  { value: "365", label: "1 year" },
                ]}
              />
            </div>
            <div>
              <Button type="submit" size="sm" icon={<ShieldOff />} disabled={reason.trim().length < 3}>
                Accept risk
              </Button>
            </div>
          </form>
        </div>
      )}
    </Panel>
  );
}

function FindingsPage({ call, summary, reload }: { call: Call; summary?: Summary; reload: () => void }) {
  const [tab, setTab] = useState<Tab>("open");
  const [sev, setSev] = useState<string[]>([]);
  const [kev, setKev] = useState(false);
  const [fixable, setFixable] = useState(false);
  const [kind, setKind] = useState<"all" | Kind>("all");
  const [q, setQ] = useState("");
  const [rows, setRows] = useState<Vulnerability[]>();
  const [more, setMore] = useState<string>();
  const [open, setOpen] = useState<Vulnerability | null>(null);

  const query = useCallback(
    (cursor?: string) => {
      const p = new URLSearchParams({ status: tab, limit: "200" });
      if (sev.length) p.set("severity", sev.join(","));
      if (kev) p.set("kev", "true");
      if (fixable) p.set("fixable", "true");
      if (kind !== "all") p.set("kind", kind);
      if (q.trim()) p.set("q", q.trim());
      if (cursor) p.set("cursor", cursor);
      return call<{ vulnerabilities: Vulnerability[]; nextCursor?: string }>(`/api/v1/vulnerabilities?${p}`);
    },
    [call, tab, sev, kev, fixable, kind, q],
  );

  const load = useCallback(() => {
    query().then((r) => (setRows(r.vulnerabilities), setMore(r.nextCursor)), () => setRows([]));
  }, [query]);
  useEffect(load, [load]);

  const loadMore = () => more && query(more).then((r) => (setRows((x) => [...(x ?? []), ...r.vulnerabilities]), setMore(r.nextCursor)));

  const columns: Column<Vulnerability>[] = [
    { id: "sev", header: "Severity", width: "104px", cell: (v) => <SeverityBadge severity={ui(v.severity)} /> },
    {
      id: "vuln",
      header: "Vulnerability",
      width: "32%",
      cell: (v) => (
        <span className="flex min-w-0 flex-col">
          {/* Click bubbles to the row handler; the button makes it keyboard reachable. */}
          <button type="button" className="self-start font-mono text-xs font-medium text-fg hover:underline">
            {v.vulnerability}
          </button>
          <span className="vulns-clamp text-xs text-fg-muted" title={v.description ?? undefined}>
            {v.description ?? ""}
          </span>
        </span>
      ),
    },
    {
      id: "pkg",
      header: "Package",
      width: "24%",
      cell: (v) => (
        <span className="flex min-w-0 flex-col">
          <span className="vulns-wrap font-mono text-xs font-medium" title={v.package.packages.join(", ")}>
            {v.package.name}
            {v.package.packages.some((p) => p !== v.package.name) && <span className="font-normal text-fg-muted"> ({v.package.packages.join(", ")})</span>}
          </span>
          <FixCell fix={v.fix} versions={v.package.versions.join(", ")} />
        </span>
      ),
    },
    { id: "affected", header: "Affected", width: "140px", align: "right", cell: (v) => <span className="whitespace-nowrap">{affected(v)}</span> },
    { id: "epss", header: "EPSS", width: "72px", align: "right", mono: true, description: "Probability of exploitation in the next 30 days.", cell: (v) => pct(v.epss) },
    {
      id: "context",
      header: "Context",
      cell: (v) => (
        <span className="flex flex-wrap gap-1">
          {v.knownExploited && <Badge tone="danger">Exploited</Badge>}
          {v.ransomware && <Badge tone="critical">Ransomware</Badge>}
          {v.fix.state === "fixed" ? <Badge tone="success">Fix available</Badge> : <Badge>{v.fix.state === "wont-fix" ? "Won't fix" : "No fix yet"}</Badge>}
        </span>
      ),
    },
  ];

  const s = summary;
  return (
    <>
      <PageHeader
        title="Findings"
        description={s ? `${plural(s.assets.hosts, "host")} · ${plural(s.assets.images, "image")} · vulnerability data ${s.feed.built ? `built ${ago(s.feed.built)}` : "not downloaded yet"} (OS advisories, GitHub, NVD, CISA KEV, EPSS)` : undefined}
        actions={<SearchInput label="Search CVE or package" className="w-64" value={q} onChange={(e) => setQ(e.target.value)} />}
      />
      <NoFeed feed={s?.feed} />
      {s && (
        <KpiGrid minWidth={150}>
          <KpiCard label="Exploited (KEV)" value={s.knownExploited} tone={s.knownExploited ? "danger" : "success"} />
          <KpiCard label="Critical" value={s.open.critical} footer={<SeverityBadge severity="critical" />} />
          <KpiCard label="High" value={s.open.high} footer={<SeverityBadge severity="high" />} />
          <KpiCard label="Medium" value={s.open.medium} footer={<SeverityBadge severity="medium" />} />
          <KpiCard label="Low" value={s.open.low} footer={<SeverityBadge severity="low" />} />
          <KpiCard label="Fix available" value={s.fixable} tone="info" />
        </KpiGrid>
      )}
      <Tabs<Tab>
        label="Finding views"
        value={tab}
        onChange={setTab}
        items={[
          { value: "open", label: "Fix first" },
          { value: "excepted", label: "Accepted risk" },
        ]}
      />
      <FilterBar
        onClear={() => {
          setSev([]);
          setKev(false);
          setFixable(false);
          setKind("all");
          setQ("");
        }}
      >
        <FacetFilter
          label="Severity"
          selected={sev}
          onChange={setSev}
          options={[
            { value: "critical", label: "Critical", count: s?.open.critical },
            { value: "high", label: "High", count: s?.open.high },
            { value: "medium", label: "Medium", count: s?.open.medium },
            { value: "low", label: "Low", count: s?.open.low },
            { value: "negligible", label: "Negligible", count: s?.open.negligible },
          ]}
        />
        <SegmentedControl
          label="Asset kind"
          size="sm"
          value={kind}
          onChange={setKind}
          options={[
            { value: "all", label: "All" },
            { value: "host", label: "Hosts" },
            { value: "image", label: "Images" },
          ]}
        />
        <Switch checked={kev} onCheckedChange={setKev} label="Exploited only" />
        <Switch checked={fixable} onCheckedChange={setFixable} label="Fix available" />
      </FilterBar>
      <div className={open ? "grid gap-2.5 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]" : "grid gap-2.5"}>
        <Panel
          title={tab === "open" ? "Fix first" : "Accepted risk"}
          description="Ranked by known exploitation, then risk (severity and EPSS)"
          flush
          footer={
            more ? (
              <Button size="sm" onClick={loadMore}>
                Load more
              </Button>
            ) : undefined
          }
        >
          <DataTable
            label="Vulnerability findings"
            columns={columns}
            rows={rows ?? []}
            loading={!rows}
            getRowId={rowId}
            onRowClick={(v) => setOpen(v)}
            activeRowId={open ? rowId(open) : undefined}
            minWidth={960}
            pageSize={50}
            empty={
              <EmptyState title={tab === "open" ? "No open findings" : "No accepted risks"}>
                {s && s.assets.hosts + s.assets.images === 0 ? (
                  <>
                    Nothing has been scanned yet. See <a href="#/setup">Setup</a> to add hosts and images.
                  </>
                ) : (
                  "Nothing matches these filters."
                )}
              </EmptyState>
            }
          />
        </Panel>
        {open && (
          <VulnPanel
            id={open.vulnerability}
            call={call}
            onClose={() => setOpen(null)}
            onChanged={() => {
              setOpen(null);
              load();
              reload();
            }}
          />
        )}
      </div>
    </>
  );
}

// ---------------------------------------------------------------- Hosts and images

function MatchStatus({ a }: { a: Asset }) {
  if (a.match.status === "failed") return <StatusBadge tone="danger" title={a.match.error ?? undefined}>Failed</StatusBadge>;
  if (a.match.status !== "done") return <StatusBadge tone="info" title={a.match.error ?? undefined}>{a.match.status === "matching" ? "Matching" : "Queued"}</StatusBadge>;
  return <span className="text-xs text-fg-muted">{ago(a.match.matchedAt)}</span>;
}

function AssetsPage({ call, kind }: { call: Call; kind: Kind }) {
  const [rows, setRows] = useState<Asset[]>();
  useEffect(() => {
    setRows(undefined);
    const load = () => call<{ assets: Asset[] }>(`/api/v1/assets?kind=${kind}&limit=500`).then((r) => setRows(r.assets), () => setRows([]));
    load();
    const t = setInterval(load, 15_000);
    return () => clearInterval(t);
  }, [call, kind]);

  const columns: Column<Asset>[] = [
    {
      id: "name",
      header: kind === "host" ? "Host" : "Image",
      width: "28%",
      sortValue: (a) => a.name,
      cell: (a) => (
        <span className="flex min-w-0 flex-col">
          <button type="button" className="self-start truncate font-mono text-xs font-medium text-fg hover:underline">
            {a.name}
          </button>
          <span className="flex flex-wrap items-center gap-1 text-xs text-fg-muted">
            {a.agent?.platform === "kubernetes" && <Badge tone="info">Kubernetes node</Badge>}
            {a.distro ?? "Unknown OS"} · {a.packages} packages
          </span>
        </span>
      ),
    },
    { id: "open", header: "Open", sortValue: (a) => a.open.critical * 1e6 + a.open.high * 1e4 + a.open.medium * 100 + a.open.low, cell: (a) => <SevCounts counts={a.open} /> },
    { id: "kev", header: "Exploited", align: "right", mono: true, sortValue: (a) => a.knownExploited, cell: (a) => (a.knownExploited ? <Badge tone="danger">{a.knownExploited}</Badge> : "0") },
    { id: "fixable", header: "Fixable", align: "right", mono: true, sortValue: (a) => a.fixable, cell: (a) => a.fixable },
    { id: "sbom", header: "Last SBOM", sortValue: (a) => a.sbom.receivedAt, cell: (a) => <span className="text-xs text-fg-muted">{ago(a.sbom.receivedAt)}</span> },
    { id: "match", header: "Matched", cell: (a) => <MatchStatus a={a} /> },
    ...(kind === "host"
      ? [
          {
            id: "agent",
            header: "Agent",
            cell: (a: Asset) =>
              a.agent ? (
                <StatusBadge tone={a.agent.lastError ? "warning" : Date.now() - Date.parse(a.agent.lastSeen) > 5 * 60_000 ? "danger" : "success"} title={a.agent.lastError ?? undefined}>
                  {a.agent.version} · {ago(a.agent.lastSeen)}
                </StatusBadge>
              ) : (
                <span className="text-xs text-fg-muted">None</span>
              ),
          } satisfies Column<Asset>,
        ]
      : []),
  ];

  return (
    <>
      <PageHeader
        title={kind === "host" ? "Hosts" : "Images"}
        description={kind === "host" ? "Hosts report through vulns-agent, which sends an SBOM of the host's packages." : "Images arrive as SBOMs sent from CI after each build."}
      />
      <Panel flush>
        <DataTable
          label={kind === "host" ? "Hosts" : "Images"}
          columns={columns}
          rows={rows ?? []}
          loading={!rows}
          getRowId={(a) => a.id}
          onRowClick={(a) => go(`#/assets/${a.id}`)}
          defaultSort={{ id: "open", direction: "desc" }}
          minWidth={900}
          pageSize={50}
          empty={
            <EmptyState title={kind === "host" ? "No hosts yet" : "No images yet"}>
              See <a href="#/setup">Setup</a> for how to {kind === "host" ? "run vulns-agent on a host" : "send image SBOMs from CI"}.
            </EmptyState>
          }
        />
      </Panel>
    </>
  );
}

type FindingTab = "open" | "excepted" | "resolved";

function AssetPage({ call, id }: { call: Call; id: string }) {
  const [asset, setAsset] = useState<Asset | null>();
  const [tab, setTab] = useState<FindingTab>("open");
  const [rows, setRows] = useState<Finding[]>();
  const [note, setNote] = useState<string>();

  useEffect(() => {
    call<Asset>(`/api/v1/assets/${id}`).then(setAsset, () => setAsset(null));
  }, [call, id]);
  useEffect(() => {
    setRows(undefined);
    call<{ findings: Finding[] }>(`/api/v1/assets/${id}/findings?status=${tab}&limit=500`).then((r) => setRows(r.findings), () => setRows([]));
  }, [call, id, tab]);

  if (asset === null) return <EmptyState title="Not found">This host or image no longer exists.</EmptyState>;
  if (!asset) return null;

  const scan = () => call(`/api/v1/assets/${id}/scan`, { method: "POST" }).then(() => setNote("The agent scans on its next heartbeat, within a minute."), (e: Error) => setNote(e.message));
  const download = async () => {
    const res = await fetch(`/api/v1/assets/${id}/sbom`, { headers: { authorization: `Bearer ${readToken()}` } });
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = `${asset.name.replace(/[^A-Za-z0-9._-]/g, "_")}.${asset.sbom.format}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };
  const remove = () => {
    if (!window.confirm(`Delete ${asset.name}, its SBOM and its findings?`)) return;
    void call(`/api/v1/assets/${id}`, { method: "DELETE" }).then(() => go(asset.kind === "host" ? "#/hosts" : "#/images"));
  };

  const columns: Column<Finding>[] = [
    { id: "sev", header: "Severity", width: "104px", cell: (f) => <SeverityBadge severity={ui(f.severity)} /> },
    {
      id: "vuln",
      header: "Vulnerability",
      width: "34%",
      cell: (f) => (
        <span className="flex min-w-0 flex-col">
          <span className="font-mono text-xs font-medium">{f.vulnerability}</span>
          <span className="vulns-clamp text-xs text-fg-muted" title={f.description ?? undefined}>
            {f.description ?? ""}
          </span>
        </span>
      ),
    },
    {
      id: "pkg",
      header: "Package",
      cell: (f) => (
        <span className="flex min-w-0 flex-col">
          <span className="vulns-wrap font-mono text-xs font-medium">{f.package.name}</span>
          <FixCell fix={f.fix} versions={f.package.version} />
        </span>
      ),
    },
    { id: "epss", header: "EPSS", align: "right", mono: true, cell: (f) => pct(f.epss) },
    { id: "kev", header: "Context", cell: (f) => (f.knownExploited ? <Badge tone="danger">Exploited</Badge> : null) },
    { id: "seen", header: tab === "resolved" ? "Resolved" : "First seen", cell: (f) => <span className="text-xs text-fg-muted">{ago(tab === "resolved" ? f.resolvedAt : f.firstSeen)}</span> },
  ];

  return (
    <>
      <PageHeader
        title={asset.name}
        breadcrumbs={[{ label: asset.kind === "host" ? "Hosts" : "Images", href: asset.kind === "host" ? "#/hosts" : "#/images" }, { label: asset.name }]}
        description={`${asset.agent?.platform === "kubernetes" ? "Kubernetes node · " : ""}${asset.distro ?? "Unknown OS"} · ${asset.packages} packages · SBOM ${ago(asset.sbom.receivedAt)} (${asset.sbom.format})`}
        actions={
          <>
            {asset.kind === "host" && asset.agent && (
              <Button icon={<Play />} onClick={scan}>
                Scan now
              </Button>
            )}
            <Button icon={<Download />} onClick={download}>
              SBOM
            </Button>
            <Button variant="danger" icon={<Trash2 />} onClick={remove}>
              Delete
            </Button>
          </>
        }
      />
      {note && (
        <Callout tone="info" title={note} onDismiss={() => setNote(undefined)} />
      )}
      {asset.match.status === "failed" && <Callout tone="danger" title="Matching failed">{asset.match.error}</Callout>}
      {asset.agent?.lastError && <Callout tone="warning" title="The agent reported a problem">{asset.agent.lastError}</Callout>}
      <KpiGrid minWidth={150}>
        <KpiCard label="Exploited (KEV)" value={asset.knownExploited} tone={asset.knownExploited ? "danger" : "success"} />
        <KpiCard label="Critical" value={asset.open.critical} />
        <KpiCard label="High" value={asset.open.high} />
        <KpiCard label="Medium" value={asset.open.medium} />
        <KpiCard label="Fix available" value={asset.fixable} tone="info" />
      </KpiGrid>
      <Tabs<FindingTab>
        label="Findings"
        value={tab}
        onChange={setTab}
        items={[
          { value: "open", label: "Open" },
          { value: "excepted", label: "Accepted risk" },
          { value: "resolved", label: "Resolved" },
        ]}
      />
      <Panel flush>
        <DataTable
          label={`Findings on ${asset.name}`}
          columns={columns}
          rows={rows ?? []}
          loading={!rows}
          getRowId={(f) => `${f.vulnerability}|${f.package.type}|${f.package.name}|${f.package.version}`}
          minWidth={900}
          pageSize={50}
          empty={<EmptyState title="Nothing here">{tab === "resolved" ? "Fixed findings appear here for the retention period." : "No findings in this view."}</EmptyState>}
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Exceptions

function ExceptionsPage({ call, reload }: { call: Call; reload: () => void }) {
  const [rows, setRows] = useState<Exception[]>();
  const load = useCallback(() => call<{ exceptions: Exception[] }>("/api/v1/exceptions").then((r) => setRows(r.exceptions), () => setRows([])), [call]);
  useEffect(() => void load(), [load]);

  const columns: Column<Exception>[] = [
    { id: "vuln", header: "Vulnerability", cell: (e) => <EntityChip kind="cve" value={e.vulnerability} /> },
    { id: "scope", header: "On", cell: (e) => (e.asset ? <EntityChip kind={e.asset.kind === "host" ? "host" : "container"} value={e.asset.name} href={`#/assets/${e.asset.id}`} /> : "Every asset") },
    { id: "reason", header: "Reason", width: "36%", cell: (e) => <span className="text-xs">{e.reason}</span> },
    { id: "expires", header: "Expires", sortValue: (e) => e.expiresAt, cell: (e) => <span className="text-xs">{new Date(e.expiresAt).toLocaleDateString()}</span> },
    { id: "state", header: "State", cell: (e) => (e.active ? <StatusBadge tone="success">Active</StatusBadge> : <StatusBadge tone="neutral">Expired</StatusBadge>) },
    {
      id: "remove",
      header: <span className="sr-only">Remove</span>,
      label: "Remove",
      align: "right",
      cell: (e) => (
        <IconButton label={`Remove the exception for ${e.vulnerability}`} size="sm" onClick={() => void call(`/api/v1/exceptions/${e.id}`, { method: "DELETE" }).then(() => (load(), reload()))}>
          <Trash2 />
        </IconButton>
      ),
    },
  ];
  return (
    <>
      <PageHeader title="Exceptions" description="Accepted risks hide a vulnerability until they expire. Add one from a finding's details." />
      <Panel flush>
        <DataTable label="Exceptions" columns={columns} rows={rows ?? []} loading={!rows} getRowId={(e) => e.id} minWidth={800} empty={<EmptyState title="No exceptions">Every open finding is shown.</EmptyState>} />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Setup

function Code({ children }: { children: ReactNode }) {
  return <pre className="m-0 overflow-x-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs text-fg">{children}</pre>;
}

function SetupPage({ call, feed, reload, version }: { call: Call; feed?: Feed; reload: () => void; version?: string }) {
  const origin = window.location.origin;
  const tag = version ?? "<version>";
  const [hostsOn, setHostsOn] = useState<"docker" | "kubernetes">("docker");
  const update = () => void call("/api/v1/feed/update", { method: "POST" }).then(reload);
  return (
    <>
      <PageHeader title="Setup" description="Where the vulnerability data comes from, and how hosts and images get here." />
      <Panel
        title="Vulnerability data"
        description="Grype's database: distribution advisories (Debian, Ubuntu, RHEL, Alpine and more), GitHub advisories, NVD, CISA KEV and EPSS. Only this data is downloaded; nothing about this install is sent."
        actions={
          <Button size="sm" icon={<RefreshCw />} onClick={update} loading={feed?.updating} disabled={feed?.updating}>
            Update now
          </Button>
        }
      >
        <dl className="vulns-pairs text-sm">
          <dt className="text-fg-muted">Built</dt>
          <dd className="m-0">{feed?.built ? `${new Date(feed.built).toLocaleString()} (${ago(feed.built)})` : "Not downloaded yet"}</dd>
          <dt className="text-fg-muted">Schema</dt>
          <dd className="m-0 font-mono">{feed?.schema ?? "–"}</dd>
          <dt className="text-fg-muted">Last check</dt>
          <dd className="m-0">{ago(feed?.checkedAt)}</dd>
          {feed?.error && (
            <>
              <dt className="text-fg-muted">Last error</dt>
              <dd className="m-0 text-danger">{feed.error}</dd>
            </>
          )}
        </dl>
        <p className="mt-3 mb-1 text-sm text-fg-muted">Without internet access, download the archive on another machine and upload it:</p>
        <Code>{`grype db download -o vulnerability-db.tar.zst   # or the URL from: grype db list
curl -sf -X PUT -H "Authorization: Bearer $VULNS_ADMIN_TOKEN" -H 'content-type: application/zstd' \\
  --data-binary @vulnerability-db.tar.zst ${origin}/api/v1/feed`}</Code>
      </Panel>
      <Panel
        title="Hosts"
        description="vulns-agent reads a host's package databases through a read-only mount, as an unprivileged user, and only sends the SBOM here. It needs the ingest token (VULNS_INGEST_TOKEN)."
        actions={
          <SegmentedControl
            label="Where the hosts run"
            size="sm"
            value={hostsOn}
            onChange={setHostsOn}
            options={[
              { value: "docker", label: "Docker" },
              { value: "kubernetes", label: "Kubernetes" },
            ]}
          />
        }
      >
        {hostsOn === "docker" ? (
          <>
            <p className="mb-1 text-sm text-fg-muted">On each host:</p>
            <Code>{`docker run -d --name vulns-agent --restart unless-stopped --hostname "$(hostname)" \\
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \\
  -v /:/host:ro -e VULNS_URL=${origin} -e VULNS_INGEST_TOKEN=... \\
  ghcr.io/openasy/vulns-agent:${tag}`}</Code>
          </>
        ) : (
          <>
            <p className="mb-1 text-sm text-fg-muted">
              Once per cluster: the Helm chart runs vulns-agent on every node, new nodes included. Nodes appear under Hosts as Kubernetes nodes.
            </p>
            <Code>{`helm install vulns-agent oci://ghcr.io/openasy/charts/vulns --version ${tag} \\
  --namespace openasy --create-namespace \\
  --set vulns.enabled=false --set agent.url=${origin} --set auth.ingestToken=...`}</Code>
            <p className="mt-2 text-sm text-fg-muted">
              The agent mounts each node's / read-only (hostPath), which the Pod Security baseline and restricted levels forbid. If your cluster enforces them, allow it for this namespace with{" "}
              <code className="font-mono text-xs">kubectl label namespace openasy pod-security.kubernetes.io/enforce=privileged</code>. Clusters that forbid hostPath entirely, such as GKE Autopilot, cannot run it.
            </p>
          </>
        )}
      </Panel>
      <Panel title="Images" description="Send an SBOM from CI after each build. With wait=true the answer holds the findings, so the job can fail on them.">
        <Code>{`syft "$IMAGE" -o syft-json | curl -sf -X POST -H "Authorization: Bearer $VULNS_INGEST_TOKEN" \\
  -H 'content-type: application/json' --data-binary @- \\
  "${origin}/api/v1/sboms?kind=image&name=$IMAGE&wait=true" > result.json
jq -e '.knownExploited == 0 and .open.critical == 0' result.json   # fail the build`}</Code>
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Follows the operating system's light or dark setting (ADR 0007) until @openasy/ui ships its own system theme. */
function useSystemTheme(): "light" | "dark" {
  const query = "(prefers-color-scheme: dark)";
  const [dark, setDark] = useState(() => window.matchMedia?.(query).matches ?? false);
  useEffect(() => {
    const mq = window.matchMedia?.(query);
    const onChange = (e: MediaQueryListEvent) => setDark(e.matches);
    mq?.addEventListener("change", onChange);
    return () => mq?.removeEventListener("change", onChange);
  }, []);
  return dark ? "dark" : "light";
}

export function App() {
  const theme = useSystemTheme();
  const [version, setVersion] = useState<string>();
  const [token, setToken] = useState(readToken);
  const [authError, setAuthError] = useState<string>();
  const [route, setRoute] = useState<Route>(() => parseRoute(window.location.hash));
  const [summary, setSummary] = useState<Summary>();

  useEffect(() => {
    void api<{ version: string }>("/api/v1/version", "").then((v) => setVersion(v.version));
    const onHash = () => setRoute(parseRoute(window.location.hash));
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const onUnauthorized = useCallback((msg?: string) => {
    setAuthError(msg);
    saveToken("");
    setToken("");
  }, []);
  const call = useApi(token, onUnauthorized);

  const reload = useCallback(() => void call<Summary>("/api/v1/summary").then(setSummary, () => {}), [call]);
  useEffect(() => {
    if (!token) return;
    reload();
    const t = setInterval(reload, 15_000);
    return () => clearInterval(t);
  }, [token, reload]);

  const nav = [
    { id: "findings", label: "Findings", icon: TriangleAlert },
    { id: "hosts", label: "Hosts", icon: Server, count: summary?.assets.hosts },
    { id: "images", label: "Images", icon: Boxes, count: summary?.assets.images },
    { id: "exceptions", label: "Exceptions", icon: ShieldOff },
  ];
  const active = route.page === "asset" ? undefined : route.page;

  return (
    <BrandProvider theme={theme} className="min-h-screen">
      <AppShell product="vulnerabilities" nav={nav} activeNav={active} onNavigate={(id) => go(`#/${id}`)} footerNav={[{ id: "setup", label: "Setup", icon: Settings2 }]}>
        <Callout tone="warning" title="For testing only">
          This release (vulns {version ?? "…"}) has no sign-in: everyone with the admin token can see and change everything. The API reference is at <a href="/api/docs/">/api/docs/</a>.
        </Callout>
        {!token ? (
          <TokenForm
            error={authError}
            onToken={(t) => {
              saveToken(t);
              setToken(t);
            }}
          />
        ) : route.page === "findings" ? (
          <FindingsPage call={call} summary={summary} reload={reload} />
        ) : route.page === "hosts" || route.page === "images" ? (
          <AssetsPage key={route.page} call={call} kind={route.page === "hosts" ? "host" : "image"} />
        ) : route.page === "asset" ? (
          <AssetPage key={route.id} call={call} id={route.id} />
        ) : route.page === "exceptions" ? (
          <ExceptionsPage call={call} reload={reload} />
        ) : (
          <SetupPage call={call} feed={summary?.feed} reload={reload} version={version} />
        )}
      </AppShell>
    </BrandProvider>
  );
}
