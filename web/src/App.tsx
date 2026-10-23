import {
  AppShell,
  Badge,
  BrandProvider,
  Button,
  Callout,
  DataTable,
  Dialog,
  EmptyState,
  EntityChip,
  FacetFilter,
  FilterBar,
  IconButton,
  KpiCard,
  KpiGrid,
  navigate,
  PageHeader,
  Panel,
  PRODUCT_IDS,
  SearchInput,
  SegmentedControl,
  SelectField,
  SeverityBadge,
  StatusBadge,
  Switch,
  Tabs,
  TextField,
  usePath,
  type Column,
  type ProductId,
  type Severity as UiSeverity,
  useThemePreference,
  useAgo,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAuth } from "@openasy/auth/react";
import {
  Boxes,
  Download,
  KeyRound,
  LogIn,
  LogOut,
  Play,
  RefreshCw,
  Server,
  Settings2,
  ShieldOff,
  Trash2,
  TriangleAlert,
  UserRound,
  Users,
  X,
} from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  MfaSetupRequired,
  Unauthorized,
  type Asset,
  type Counts,
  type Exception,
  type Feed,
  type Finding,
  type Kind,
  type ProductLink,
  type Severity,
  type HostsCoverage,
  type Summary,
  type Vulnerability,
  type VulnerabilityDetail,
} from "./api.ts";
import { useT, type T } from "./i18n.ts";

// Grype's "negligible" and "unknown" have no level of their own in the shared scale.
const ui = (s: Severity): UiSeverity => (s === "negligible" || s === "unknown" ? "info" : s);
const pct = (v: number | null) => (v === null ? "–" : `${(v * 100).toFixed(1)}%`);

const PAGES = ["hosts", "images", "exceptions", "setup", "account", "members", "signin", "tokens"] as const;
type Route = { page: "findings" | (typeof PAGES)[number] } | { page: "asset"; id: string };
/** The first path segments that are pages of this UI, for followLinks. */
export const PATHS = ["findings", "assets", ...PAGES];
function parseRoute(path: string): Route {
  const [page, id] = path.replace(/^\//, "").split("/");
  if (page === "assets" && id) return { page: "asset", id: decodeURIComponent(id) };
  if ((PAGES as readonly string[]).includes(page ?? "")) return { page: page as (typeof PAGES)[number] };
  return { page: "findings" };
}

/** Data loading with the session; when it ends, the sign-in screen comes back. */
function useApi() {
  const { expired, refresh } = useAuth();
  return useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      try {
        return await api<T>(path, init);
      } catch (err) {
        if (err instanceof Unauthorized) expired();
        if (err instanceof MfaSetupRequired) void refresh();
        throw err;
      }
    },
    [expired, refresh],
  );
}
type Call = ReturnType<typeof useApi>;

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
  const t = useT();
  return (
    <span className="flex min-w-0 flex-col font-mono text-xs">
      <span className="vulns-wrap text-fg-muted">
        {versions} →{" "}
        {fix.version ? <span className="text-success">{fix.version}</span> : fix.state === "wont-fix" ? t("fixCell.wonTFix") : t("fixCell.noFixYet")}
      </span>
    </span>
  );
}

function NoFeed({ feed }: { feed: Feed | undefined }) {
  const t = useT();
  if (!feed || feed.built) {
    if (feed?.ageHours != null && feed.ageHours > 72) {
      return (
        <Callout tone="warning" title={t("noFeed.vulnerabilityDataIsDaysOld", { value: Math.round(feed.ageHours / 24) })}>
          {t("noFeed.newVulnerabilitiesAreMissingUntil")} {feed.error ? t("noFeed.lastUpdateFailed", { error: feed.error }) : ""} {t("noFeed.see")}{" "}
          <a href="/setup">{t("noFeed.setup")}</a>.
        </Callout>
      );
    }
    return null;
  }
  return (
    <Callout tone="info" title={feed.updating ? t("noFeed.downloadingVulnerabilityData") : t("noFeed.noVulnerabilityDataYet")}>
      {feed.updating
        ? t("noFeed.theFirstDownloadIsAbout")
        : feed.error
          ? t("noFeed.theDownloadFailedImportIt", { error: feed.error })
          : t("noFeed.downloadOrImportItFrom")}
    </Callout>
  );
}
const affected = (t: T, v: Vulnerability) =>
  [v.hosts && t("plurals.host", { count: v.hosts }), v.images && t("plurals.image", { count: v.images })].filter(Boolean).join(" · ");
const rowId = (v: Vulnerability) => `${v.vulnerability}|${v.package.type}|${v.package.name}`;

type Tab = "open" | "excepted";

function VulnPanel({ id, call, onClose, onChanged }: { id: string; call: Call; onClose: () => void; onChanged: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [detail, setDetail] = useState<VulnerabilityDetail>();
  const [days, setDays] = useState("90");
  const [reason, setReason] = useState("");
  const [scope, setScope] = useState("all");
  const [error, setError] = useState<string>();
  const [accepting, setAccepting] = useState(false);
  const close = () => (setAccepting(false), setReason(""), setError(undefined));

  useEffect(() => {
    setDetail(undefined);
    call<VulnerabilityDetail>(`/api/v1/vulnerabilities/${encodeURIComponent(id)}`).then(setDetail, () => setDetail(undefined));
  }, [id, call]);

  const accept = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await call("/api/v1/exceptions", {
        method: "POST",
        body: JSON.stringify({
          vulnerability: id,
          reason,
          expiresAt: new Date(Date.now() + Number(days) * 86_400_000).toISOString(),
          ...(scope !== "all" && { assetId: scope }),
        }),
      });
      close();
      onChanged();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <Panel
      aria-label={t("vulnPanel.details", { id })}
      title={id}
      description={detail?.aliases.length ? t("vulnPanel.also", { value: detail.aliases.join(", ") }) : undefined}
      actions={
        <IconButton label={t("vulnPanel.closeDetails")} size="sm" onClick={onClose}>
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
            {detail.knownExploited && (
              <StatusBadge tone="danger">
                {t("vulnPanel.inCisaKev")}
                {detail.kevDueDate ? t("vulnPanel.due", { kevDueDate: detail.kevDueDate }) : ""}
              </StatusBadge>
            )}
            {detail.ransomware && <Badge tone="critical">{t("vulnPanel.usedByRansomware")}</Badge>}
          </div>
          {detail.description && <p className="m-0 text-fg-muted">{detail.description}</p>}
          {detail.dataSource && (
            <a href={detail.dataSource} target="_blank" rel="noreferrer noopener" className="text-xs">
              {t("vulnPanel.advisory")}
            </a>
          )}
          <div className="flex flex-col gap-1">
            <span className="text-2xs font-medium tracking-wider text-fg-muted uppercase">{t("vulnPanel.where")}</span>
            <ul className="vulns-list flex flex-col gap-1">
              {detail.affected.map((a) => (
                <li key={`${a.asset.id}-${a.package.name}-${a.package.version}`} className="flex flex-wrap items-center gap-1.5 text-xs">
                  <EntityChip kind={a.asset.kind === "host" ? "host" : "container"} value={a.asset.name} href={`/assets/${a.asset.id}`} />
                  <span className="font-mono">
                    {a.package.name} {a.package.version} → {a.fix.version ?? t("vulnPanel.noFix")}
                  </span>
                  {a.excepted && <Badge>{t("vulnPanel.accepted")}</Badge>}
                </li>
              ))}
            </ul>
          </div>
          {can("editor") && (
            <div className="border-t border-line pt-3">
              <Button size="sm" icon={<ShieldOff />} onClick={() => setAccepting(true)}>
                {t("vulnPanel.acceptTheRisk")}
              </Button>
            </div>
          )}
          <Dialog
            open={accepting}
            onOpenChange={(open) => !open && close()}
            title={t("vulnPanel.acceptTheRiskOf", { id })}
            description={t("vulnPanel.itStopsCountingAsOpen")}
            onSubmit={accept}
            footer={
              <>
                <Button type="button" onClick={close}>
                  {t("vulnPanel.cancel")}
                </Button>
                <Button type="submit" variant="primary" icon={<ShieldOff />} disabled={reason.trim().length < 3}>
                  {t("vulnPanel.acceptRisk")}
                </Button>
              </>
            }
          >
            <TextField
              label={t("vulnPanel.reason")}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              hint={t("vulnPanel.whyItIsAcceptableFor")}
              error={error}
            />
            <div className="grid grid-cols-2 gap-2">
              <SelectField
                label={t("vulnPanel.on")}
                value={scope}
                onChange={(e) => setScope(e.target.value)}
                options={[
                  { value: "all", label: t("vulnPanel.everyAsset") },
                  ...[...new Map(detail.affected.map((a) => [a.asset.id, a.asset.name]))].map(([value, label]) => ({ value, label })),
                ]}
              />
              <SelectField
                label={t("vulnPanel.for")}
                value={days}
                onChange={(e) => setDays(e.target.value)}
                options={[
                  { value: "30", label: t("vulnPanel.n30Days") },
                  { value: "90", label: t("vulnPanel.n90Days") },
                  { value: "180", label: t("vulnPanel.n180Days") },
                  { value: "365", label: t("vulnPanel.n1Year") },
                ]}
              />
            </div>
          </Dialog>
        </div>
      )}
    </Panel>
  );
}

/** Servers in the install's hosts file Vulnerabilities has no scan for, and the file's own problems (ADR 0052). */
function HostsCoverageNote({ file }: { file?: HostsCoverage | null }) {
  const t = useT();
  if (!file) return null;
  if (file.error) {
    return (
      <Callout tone="danger" title={t("hostsCoverageNote.theHostsFileIsNot")}>
        {t("hostsCoverageNote.itsLastGoodVersionIs", { error: file.error, path: file.path })}
      </Callout>
    );
  }
  if (!file.missing.length) return null;
  return (
    <Callout
      tone="warning"
      title={t("hostsCoverageNote.inTheHostsFileNo", {
        length: file.missing.length,
        value: file.missing.length === 1 ? "server" : "servers",
        value2: file.missing.length === 1 ? "has" : "have",
      })}
    >
      {file.missing.map((h) => h.name).join(", ")}. Install vulns-agent there, or check that it reports the server under its name or address.
    </Callout>
  );
}

function FindingsPage({ call, summary, reload }: { call: Call; summary?: Summary; reload: () => void }) {
  const ago = useAgo();
  const t = useT();
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
    query().then(
      (r) => (setRows(r.vulnerabilities), setMore(r.nextCursor)),
      () => setRows([]),
    );
  }, [query]);
  useEffect(load, [load]);

  const loadMore = () => more && query(more).then((r) => (setRows((x) => [...(x ?? []), ...r.vulnerabilities]), setMore(r.nextCursor)));

  const columns: Column<Vulnerability>[] = [
    { id: "sev", header: t("findingsPage.severity"), width: "104px", cell: (v) => <SeverityBadge severity={ui(v.severity)} /> },
    {
      id: "vuln",
      header: t("findingsPage.vulnerability"),
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
      header: t("findingsPage.package"),
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
    {
      id: "affected",
      header: t("findingsPage.affected"),
      width: "140px",
      align: "right",
      cell: (v) => <span className="whitespace-nowrap">{affected(t, v)}</span>,
    },
    {
      id: "epss",
      header: "EPSS",
      width: "72px",
      align: "right",
      mono: true,
      description: t("findingsPage.probabilityOfExploitationInThe"),
      cell: (v) => pct(v.epss),
    },
    {
      id: "context",
      header: t("findingsPage.context"),
      cell: (v) => (
        <span className="flex flex-wrap gap-1">
          {v.knownExploited && <Badge tone="danger">{t("findingsPage.exploited")}</Badge>}
          {v.ransomware && <Badge tone="critical">{t("findingsPage.ransomware")}</Badge>}
          {v.fix.state === "fixed" ? (
            <Badge tone="success">{t("findingsPage.fixAvailable")}</Badge>
          ) : (
            <Badge>{v.fix.state === "wont-fix" ? t("findingsPage.wonTFix") : t("findingsPage.noFixYet")}</Badge>
          )}
        </span>
      ),
    },
  ];

  const s = summary;
  return (
    <>
      <PageHeader
        title={t("findingsPage.findings")}
        description={
          s
            ? t("findingsPage.vulnerabilityDataOsAdvisoriesGithub", {
                plural: t("plurals.host", { count: s.assets.hosts }),
                plural2: t("plurals.image", { count: s.assets.images }),
                value: s.feed.built ? `built ${ago(s.feed.built)}` : "not downloaded yet",
              })
            : undefined
        }
        actions={<SearchInput label={t("findingsPage.searchCveOrPackage")} className="w-64" value={q} onChange={(e) => setQ(e.target.value)} />}
      />
      <HostsCoverageNote file={s?.hostsFile} />
      <NoFeed feed={s?.feed} />
      {s && (
        <KpiGrid minWidth={150}>
          <KpiCard label={t("findingsPage.exploitedKev")} value={s.knownExploited} tone={s.knownExploited ? "danger" : "success"} />
          <KpiCard label={t("findingsPage.critical")} value={s.open.critical} footer={<SeverityBadge severity="critical" />} />
          <KpiCard label={t("findingsPage.high")} value={s.open.high} footer={<SeverityBadge severity="high" />} />
          <KpiCard label={t("findingsPage.medium")} value={s.open.medium} footer={<SeverityBadge severity="medium" />} />
          <KpiCard label={t("findingsPage.low")} value={s.open.low} footer={<SeverityBadge severity="low" />} />
          <KpiCard label={t("findingsPage.fixAvailable")} value={s.fixable} tone="info" />
        </KpiGrid>
      )}
      <Tabs<Tab>
        label={t("findingsPage.findingViews")}
        value={tab}
        onChange={setTab}
        items={[
          { value: "open", label: t("findingsPage.fixFirst") },
          { value: "excepted", label: t("findingsPage.acceptedRisk") },
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
          label={t("findingsPage.severity")}
          selected={sev}
          onChange={setSev}
          options={[
            { value: "critical", label: t("findingsPage.critical"), count: s?.open.critical },
            { value: "high", label: t("findingsPage.high"), count: s?.open.high },
            { value: "medium", label: t("findingsPage.medium"), count: s?.open.medium },
            { value: "low", label: t("findingsPage.low"), count: s?.open.low },
            { value: "negligible", label: t("findingsPage.negligible"), count: s?.open.negligible },
          ]}
        />
        <SegmentedControl
          label={t("findingsPage.assetKind")}
          size="sm"
          value={kind}
          onChange={setKind}
          options={[
            { value: "all", label: t("findingsPage.all") },
            { value: "host", label: t("findingsPage.hosts") },
            { value: "image", label: t("findingsPage.images") },
          ]}
        />
        <Switch checked={kev} onCheckedChange={setKev} label={t("findingsPage.exploitedOnly")} />
        <Switch checked={fixable} onCheckedChange={setFixable} label={t("findingsPage.fixAvailable")} />
      </FilterBar>
      <div className={open ? "grid gap-2.5 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]" : "grid gap-2.5"}>
        <Panel
          title={tab === "open" ? t("findingsPage.fixFirst") : t("findingsPage.acceptedRisk")}
          description={t("findingsPage.rankedByKnownExploitationThen")}
          flush
          footer={
            more ? (
              <Button size="sm" onClick={loadMore}>
                {t("findingsPage.loadMore")}
              </Button>
            ) : undefined
          }
        >
          <DataTable
            label={t("findingsPage.vulnerabilityFindings")}
            columns={columns}
            rows={rows ?? []}
            loading={!rows}
            getRowId={rowId}
            onRowClick={(v) => setOpen(v)}
            activeRowId={open ? rowId(open) : undefined}
            minWidth={960}
            pageSize={50}
            empty={
              <EmptyState title={tab === "open" ? t("findingsPage.noOpenFindings") : t("findingsPage.noAcceptedRisks")}>
                {s && s.assets.hosts + s.assets.images === 0 ? (
                  <>
                    {t("findingsPage.nothingHasBeenScannedYet")} <a href="/setup">{t("findingsPage.setup")}</a> to add hosts and images.
                  </>
                ) : (
                  t("findingsPage.nothingMatchesTheseFilters")
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
  const ago = useAgo();
  const t = useT();
  if (a.match.status === "failed")
    return (
      <StatusBadge tone="danger" title={a.match.error ?? undefined}>
        {t("matchStatus.failed")}
      </StatusBadge>
    );
  if (a.match.status !== "done")
    return (
      <StatusBadge tone="info" title={a.match.error ?? undefined}>
        {a.match.status === "matching" ? t("matchStatus.matching") : t("matchStatus.queued")}
      </StatusBadge>
    );
  return <span className="text-xs text-fg-muted">{ago(a.match.matchedAt)}</span>;
}

function AssetsPage({ call, kind }: { call: Call; kind: Kind }) {
  const ago = useAgo();
  const msg = useT();
  const [rows, setRows] = useState<Asset[]>();
  useEffect(() => {
    setRows(undefined);
    const load = () =>
      call<{ assets: Asset[] }>(`/api/v1/assets?kind=${kind}&limit=500`).then(
        (r) => setRows(r.assets),
        () => setRows([]),
      );
    load();
    const t = setInterval(load, 15_000);
    return () => clearInterval(t);
  }, [call, kind]);

  const columns: Column<Asset>[] = [
    {
      id: "name",
      header: kind === "host" ? msg("assetsPage.host") : msg("assetsPage.image"),
      width: "28%",
      sortValue: (a) => a.name,
      cell: (a) => (
        <span className="flex min-w-0 flex-col">
          <button type="button" className="self-start truncate font-mono text-xs font-medium text-fg hover:underline">
            {a.name}
          </button>
          <span className="flex flex-wrap items-center gap-1 text-xs text-fg-muted">
            {a.agent?.platform === "kubernetes" && <Badge tone="info">{msg("assetsPage.kubernetesNode")}</Badge>}
            {a.distro ?? msg("assetsPage.unknownOs")} · {a.packages} packages
          </span>
        </span>
      ),
    },
    {
      id: "open",
      header: msg("assetsPage.open"),
      sortValue: (a) => a.open.critical * 1e6 + a.open.high * 1e4 + a.open.medium * 100 + a.open.low,
      cell: (a) => <SevCounts counts={a.open} />,
    },
    {
      id: "kev",
      header: msg("assetsPage.exploited"),
      align: "right",
      mono: true,
      sortValue: (a) => a.knownExploited,
      cell: (a) => (a.knownExploited ? <Badge tone="danger">{a.knownExploited}</Badge> : "0"),
    },
    { id: "fixable", header: msg("assetsPage.fixable"), align: "right", mono: true, sortValue: (a) => a.fixable, cell: (a) => a.fixable },
    {
      id: "sbom",
      header: msg("assetsPage.lastSbom"),
      sortValue: (a) => a.sbom.receivedAt,
      cell: (a) => <span className="text-xs text-fg-muted">{ago(a.sbom.receivedAt)}</span>,
    },
    { id: "match", header: msg("assetsPage.matched"), cell: (a) => <MatchStatus a={a} /> },
    ...(kind === "host"
      ? [
          {
            id: "agent",
            header: msg("assetsPage.agent"),
            cell: (a: Asset) =>
              a.agent ? (
                <StatusBadge
                  tone={a.agent.lastError ? "warning" : Date.now() - Date.parse(a.agent.lastSeen) > 5 * 60_000 ? "danger" : "success"}
                  title={a.agent.lastError ?? undefined}
                >
                  {a.agent.version} · {ago(a.agent.lastSeen)}
                </StatusBadge>
              ) : (
                <span className="text-xs text-fg-muted">{msg("assetsPage.none")}</span>
              ),
          } satisfies Column<Asset>,
        ]
      : []),
  ];

  return (
    <>
      <PageHeader
        title={kind === "host" ? msg("assetsPage.hosts") : msg("assetsPage.images")}
        description={kind === "host" ? msg("assetsPage.hostsReportThroughVulnsAgent") : msg("assetsPage.imagesArriveAsSbomsSent")}
      />
      <Panel flush>
        <DataTable
          label={kind === "host" ? msg("assetsPage.hosts") : msg("assetsPage.images")}
          columns={columns}
          rows={rows ?? []}
          loading={!rows}
          getRowId={(a) => a.id}
          onRowClick={(a) => navigate(`/assets/${a.id}`)}
          defaultSort={{ id: "open", direction: "desc" }}
          minWidth={900}
          pageSize={50}
          empty={
            <EmptyState title={kind === "host" ? msg("assetsPage.noHostsYet") : msg("assetsPage.noImagesYet")}>
              {msg("assetsPage.see")} <a href="/setup">{msg("assetsPage.setup")}</a> {msg("assetsPage.forHowTo")}{" "}
              {kind === "host" ? msg("assetsPage.runVulnsAgentOnA") : msg("assetsPage.sendImageSbomsFromCi")}.
            </EmptyState>
          }
        />
      </Panel>
    </>
  );
}

type FindingTab = "open" | "excepted" | "resolved";

function AssetPage({ call, id }: { call: Call; id: string }) {
  const ago = useAgo();
  const t = useT();
  const { can } = useAuth();
  const [asset, setAsset] = useState<Asset | null>();
  const [tab, setTab] = useState<FindingTab>("open");
  const [rows, setRows] = useState<Finding[]>();
  const [note, setNote] = useState<string>();

  useEffect(() => {
    call<Asset>(`/api/v1/assets/${id}`).then(setAsset, () => setAsset(null));
  }, [call, id]);
  useEffect(() => {
    setRows(undefined);
    call<{ findings: Finding[] }>(`/api/v1/assets/${id}/findings?status=${tab}&limit=500`).then(
      (r) => setRows(r.findings),
      () => setRows([]),
    );
  }, [call, id, tab]);

  if (asset === null) return <EmptyState title={t("assetPage.notFound")}>{t("assetPage.thisHostOrImageNo")}</EmptyState>;
  if (!asset) return null;

  const scan = () =>
    call(`/api/v1/assets/${id}/scan`, { method: "POST" }).then(
      () => setNote(t("assetPage.theAgentScansOnIts")),
      (e: Error) => setNote(e.message),
    );
  const download = async () => {
    const res = await fetch(`/api/v1/assets/${id}/sbom`, { credentials: "same-origin" });
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = `${asset.name.replace(/[^A-Za-z0-9._-]/g, "_")}.${asset.sbom.format}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };
  const remove = () => {
    if (!window.confirm(t("assetPage.deleteItsSbomAndIts", { name: asset.name }))) return;
    void call(`/api/v1/assets/${id}`, { method: "DELETE" }).then(() => navigate(asset.kind === "host" ? "/hosts" : "/images"));
  };

  const columns: Column<Finding>[] = [
    { id: "sev", header: t("assetPage.severity"), width: "104px", cell: (f) => <SeverityBadge severity={ui(f.severity)} /> },
    {
      id: "vuln",
      header: t("assetPage.vulnerability"),
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
      header: t("assetPage.package"),
      cell: (f) => (
        <span className="flex min-w-0 flex-col">
          <span className="vulns-wrap font-mono text-xs font-medium">{f.package.name}</span>
          <FixCell fix={f.fix} versions={f.package.version} />
        </span>
      ),
    },
    { id: "epss", header: "EPSS", align: "right", mono: true, cell: (f) => pct(f.epss) },
    { id: "kev", header: t("assetPage.context"), cell: (f) => (f.knownExploited ? <Badge tone="danger">{t("assetPage.exploited")}</Badge> : null) },
    {
      id: "seen",
      header: tab === "resolved" ? t("assetPage.resolved") : t("assetPage.firstSeen"),
      cell: (f) => <span className="text-xs text-fg-muted">{ago(tab === "resolved" ? f.resolvedAt : f.firstSeen)}</span>,
    },
  ];

  return (
    <>
      <PageHeader
        title={asset.name}
        breadcrumbs={[
          { label: asset.kind === "host" ? t("assetPage.hosts") : t("assetPage.images"), href: asset.kind === "host" ? "/hosts" : "/images" },
          { label: asset.name },
        ]}
        description={t("assetPage.packagesSbom", {
          value: asset.agent?.platform === "kubernetes" ? "Kubernetes node · " : "",
          value2: asset.distro ?? "Unknown OS",
          packages: asset.packages,
          ago: ago(asset.sbom.receivedAt),
          format: asset.sbom.format,
        })}
        actions={
          <>
            {asset.kind === "host" && asset.agent && can("editor") && (
              <Button icon={<Play />} onClick={scan}>
                {t("assetPage.scanNow")}
              </Button>
            )}
            <Button icon={<Download />} onClick={download}>
              SBOM
            </Button>
            {can("admin") && (
              <Button variant="danger" icon={<Trash2 />} onClick={remove}>
                {t("assetPage.delete")}
              </Button>
            )}
          </>
        }
      />
      {note && <Callout tone="info" title={note} onDismiss={() => setNote(undefined)} />}
      {asset.match.status === "failed" && (
        <Callout tone="danger" title={t("assetPage.matchingFailed")}>
          {asset.match.error}
        </Callout>
      )}
      {asset.agent?.lastError && (
        <Callout tone="warning" title={t("assetPage.theAgentReportedAProblem")}>
          {asset.agent.lastError}
        </Callout>
      )}
      <KpiGrid minWidth={150}>
        <KpiCard label={t("assetPage.exploitedKev")} value={asset.knownExploited} tone={asset.knownExploited ? "danger" : "success"} />
        <KpiCard label={t("assetPage.critical")} value={asset.open.critical} />
        <KpiCard label={t("assetPage.high")} value={asset.open.high} />
        <KpiCard label={t("assetPage.medium")} value={asset.open.medium} />
        <KpiCard label={t("assetPage.fixAvailable")} value={asset.fixable} tone="info" />
      </KpiGrid>
      <Tabs<FindingTab>
        label={t("assetPage.findings")}
        value={tab}
        onChange={setTab}
        items={[
          { value: "open", label: t("assetPage.open") },
          { value: "excepted", label: t("assetPage.acceptedRisk") },
          { value: "resolved", label: t("assetPage.resolved") },
        ]}
      />
      <Panel flush>
        <DataTable
          label={t("assetPage.findingsOn", { name: asset.name })}
          columns={columns}
          rows={rows ?? []}
          loading={!rows}
          getRowId={(f) => `${f.vulnerability}|${f.package.type}|${f.package.name}|${f.package.version}`}
          minWidth={900}
          pageSize={50}
          empty={
            <EmptyState title={t("assetPage.nothingHere")}>
              {tab === "resolved" ? t("assetPage.fixedFindingsAppearHereFor") : t("assetPage.noFindingsInThisView")}
            </EmptyState>
          }
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Exceptions

function ExceptionsPage({ call, reload }: { call: Call; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [rows, setRows] = useState<Exception[]>();
  const load = useCallback(
    () =>
      call<{ exceptions: Exception[] }>("/api/v1/exceptions").then(
        (r) => setRows(r.exceptions),
        () => setRows([]),
      ),
    [call],
  );
  useEffect(() => void load(), [load]);

  const columns: Column<Exception>[] = [
    { id: "vuln", header: t("exceptionsPage.vulnerability"), cell: (e) => <EntityChip kind="cve" value={e.vulnerability} /> },
    {
      id: "scope",
      header: t("exceptionsPage.on"),
      cell: (e) =>
        e.asset ? <EntityChip kind={e.asset.kind === "host" ? "host" : "container"} value={e.asset.name} href={`/assets/${e.asset.id}`} /> : "Every asset",
    },
    { id: "reason", header: t("exceptionsPage.reason"), width: "36%", cell: (e) => <span className="text-xs">{e.reason}</span> },
    {
      id: "expires",
      header: t("exceptionsPage.expires"),
      sortValue: (e) => e.expiresAt,
      cell: (e) => <span className="text-xs">{new Date(e.expiresAt).toLocaleDateString()}</span>,
    },
    {
      id: "state",
      header: t("exceptionsPage.state"),
      cell: (e) =>
        e.active ? (
          <StatusBadge tone="success">{t("exceptionsPage.active")}</StatusBadge>
        ) : (
          <StatusBadge tone="neutral">{t("exceptionsPage.expired")}</StatusBadge>
        ),
    },
    {
      id: "remove",
      header: <span className="sr-only">{t("exceptionsPage.remove")}</span>,
      label: t("exceptionsPage.remove"),
      align: "right",
      cell: (e) =>
        can("editor") && (
          <IconButton
            label={t("exceptionsPage.removeTheExceptionFor", { vulnerability: e.vulnerability })}
            size="sm"
            onClick={() => void call(`/api/v1/exceptions/${e.id}`, { method: "DELETE" }).then(() => (load(), reload()))}
          >
            <Trash2 />
          </IconButton>
        ),
    },
  ];
  return (
    <>
      <PageHeader title={t("exceptionsPage.exceptions")} description={t("exceptionsPage.acceptedRisksHideAVulnerability")} />
      <Panel flush>
        <DataTable
          label={t("exceptionsPage.exceptions")}
          columns={columns}
          rows={rows ?? []}
          loading={!rows}
          getRowId={(e) => e.id}
          minWidth={800}
          empty={<EmptyState title={t("exceptionsPage.noExceptions")}>{t("exceptionsPage.everyOpenFindingIsShown")}</EmptyState>}
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Setup

function Code({ children }: { children: ReactNode }) {
  return <pre className="m-0 overflow-x-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs text-fg">{children}</pre>;
}

/** "1 Vulnerability data" with a numbered marker, for the first-run steps. */
function StepTitle({ n, children }: { n?: number; children: ReactNode }) {
  const t = useT();
  if (!n) return <>{children}</>;
  return (
    <span className="flex items-center gap-2">
      <span aria-hidden className="grid size-6 shrink-0 place-items-center rounded-full bg-accent-soft text-xs font-semibold text-accent-text">
        {n}
      </span>
      <span>
        <span className="sr-only">{t("stepTitle.step", { n })}</span>
        {children}
      </span>
    </span>
  );
}

function FeedPanel({ call, feed, reload, step }: { call: Call; feed?: Feed; reload: () => void; step?: number }) {
  const ago = useAgo();
  const t = useT();
  const { can } = useAuth();
  const update = () => void call("/api/v1/feed/update", { method: "POST" }).then(reload);
  return (
    <Panel
      title={<StepTitle n={step}>{t("feedPanel.vulnerabilityData")}</StepTitle>}
      description={t("feedPanel.grypeSDatabaseDistributionAdvisories")}
      actions={
        <>
          {step &&
            (feed?.built ? (
              <StatusBadge tone="success">{t("feedPanel.ready")}</StatusBadge>
            ) : feed?.updating ? (
              <StatusBadge tone="info">{t("feedPanel.downloading")}</StatusBadge>
            ) : (
              <StatusBadge tone="warning">{t("feedPanel.missing")}</StatusBadge>
            ))}
          {can("admin") && (
            <Button size="sm" icon={<RefreshCw />} onClick={update} loading={feed?.updating} disabled={feed?.updating}>
              {t("feedPanel.updateNow")}
            </Button>
          )}
        </>
      }
    >
      <dl className="vulns-pairs text-sm">
        <dt className="text-fg-muted">{t("feedPanel.built")}</dt>
        <dd className="m-0">
          {feed?.built
            ? `${new Date(feed.built).toLocaleString()} (${ago(feed.built)})`
            : feed?.updating
              ? t("feedPanel.downloadingNowAbout200Mb")
              : t("feedPanel.notDownloadedYet")}
        </dd>
        <dt className="text-fg-muted">{t("feedPanel.schema")}</dt>
        <dd className="m-0 font-mono">{feed?.schema ?? "–"}</dd>
        <dt className="text-fg-muted">{t("feedPanel.lastCheck")}</dt>
        <dd className="m-0">{ago(feed?.checkedAt)}</dd>
        {feed?.error && (
          <>
            <dt className="text-fg-muted">{t("feedPanel.lastError")}</dt>
            <dd className="m-0 text-danger">{feed.error}</dd>
          </>
        )}
      </dl>
      <p className="mt-3 mb-1 text-sm text-fg-muted">{t("feedPanel.withoutInternetAccessDownloadThe")}</p>
      <Code>{`grype db download -o vulnerability-db.tar.zst   # or the URL from: grype db list
# VULNS_API_TOKEN: an API token with the admin role, from Settings → API tokens
curl -sf -X PUT -H "Authorization: Bearer $VULNS_API_TOKEN" -H 'content-type: application/zstd' \\
  --data-binary @vulnerability-db.tar.zst ${window.location.origin}/api/v1/feed`}</Code>
    </Panel>
  );
}

function HostsPanel({ version, step }: { version?: string; step?: number }) {
  const t = useT();
  const origin = window.location.origin;
  const tag = version ?? "<version>";
  const [hostsOn, setHostsOn] = useState<"docker" | "kubernetes">("docker");
  return (
    <Panel
      title={<StepTitle n={step}>{step ? t("hostsPanel.addHosts") : t("hostsPanel.hosts")}</StepTitle>}
      description={t("hostsPanel.vulnsAgentReadsAHost")}
      actions={
        <SegmentedControl
          label={t("hostsPanel.whereTheHostsRun")}
          size="sm"
          value={hostsOn}
          onChange={setHostsOn}
          options={[
            { value: "docker", label: t("hostsPanel.docker") },
            { value: "kubernetes", label: t("hostsPanel.kubernetes") },
          ]}
        />
      }
    >
      {hostsOn === "docker" ? (
        <>
          <p className="mb-1 text-sm text-fg-muted">{t("hostsPanel.onEachHost")}</p>
          <Code>{`docker run -d --name vulns-agent --restart unless-stopped --hostname "$(hostname)" \\
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \\
  -v /:/host:ro -e VULNS_URL=${origin} -e VULNS_INGEST_TOKEN=... \\
  ghcr.io/openasy/vulns-agent:${tag}`}</Code>
        </>
      ) : (
        <>
          <p className="mb-1 text-sm text-fg-muted">{t("hostsPanel.oncePerClusterTheHelm")}</p>
          <Code>{`helm install vulns-agent oci://ghcr.io/openasy/charts/vulns --version ${tag} \\
  --namespace openasy --create-namespace \\
  --set vulns.enabled=false --set agent.url=${origin} --set auth.ingestToken=...`}</Code>
          <p className="mt-2 text-sm text-fg-muted">
            {t("hostsPanel.theAgentMountsEachNode")}{" "}
            <code className="font-mono text-xs">kubectl label namespace openasy pod-security.kubernetes.io/enforce=privileged</code>. Clusters that forbid
            hostPath entirely, such as GKE Autopilot, cannot run it.
          </p>
        </>
      )}
    </Panel>
  );
}

function ImagesPanel({ step }: { step?: number }) {
  const t = useT();
  return (
    <Panel
      title={<StepTitle n={step}>{step ? t("imagesPanel.checkImagesInCi") : t("imagesPanel.images")}</StepTitle>}
      description={t("imagesPanel.sendAnSbomFromCi")}
    >
      <Code>{`syft "$IMAGE" -o syft-json | curl -sf -X POST -H "Authorization: Bearer $VULNS_INGEST_TOKEN" \\
  -H 'content-type: application/json' --data-binary @- \\
  "${window.location.origin}/api/v1/sboms?kind=image&name=$IMAGE&wait=true" > result.json
jq -e '.knownExploited == 0 and .open.critical == 0' result.json   # fail the build`}</Code>
    </Panel>
  );
}

function SetupPage({ call, feed, reload, version }: { call: Call; feed?: Feed; reload: () => void; version?: string }) {
  const t = useT();
  return (
    <>
      <PageHeader title={t("setupPage.setup")} description={t("setupPage.whereTheVulnerabilityDataComes")} />
      <FeedPanel call={call} feed={feed} reload={reload} />
      <HostsPanel version={version} />
      <ImagesPanel />
    </>
  );
}

/** The first screen, until the first host or image arrives. The summary is polled, so it gives way by itself. */
function WelcomePage({ call, feed, reload, version }: { call: Call; feed?: Feed; reload: () => void; version?: string }) {
  const t = useT();
  return (
    <>
      <PageHeader
        title={t("welcomePage.getStarted")}
        description={t("welcomePage.threeStepsTheVulnerabilityData")}
        actions={<StatusBadge tone="info">{t("welcomePage.waitingForTheFirstHost")}</StatusBadge>}
      />
      <FeedPanel call={call} feed={feed} reload={reload} step={1} />
      <HostsPanel version={version} step={2} />
      <ImagesPanel step={3} />
      <p className="m-0 text-sm text-fg-muted">
        {t("welcomePage.vulnsAgentSendsVulnsIngest")} <a href="/tokens">{t("welcomePage.apiTokens")}</a>. Everything here is also in the{" "}
        <a href="/api/docs/">API</a>.
      </p>
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const t = useT();
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title={t("settingsPage.adminsOnly")}>{t("settingsPage.askAnAdminOfThis")}</EmptyState>;
  const titles = {
    account: ["Account", "Your profile, password, two-step verification and where you are signed in."],
    members: [
      "Members",
      "Who can sign in to this vulns, and with which role. Viewers see everything; editors also accept risks and request scans; admins also delete assets, manage vulnerability data, members and tokens.",
    ],
    signin: [
      "Sign-in",
      "Identity providers people can sign in with, such as OpenAsy Identity, Keycloak or Microsoft Entra ID, and which of their groups give which role.",
    ],
    tokens: ["API tokens", "For scripts and CI. Each token has one role and an expiry; the secret is shown once."],
  } as const;
  return (
    <>
      <PageHeader
        title={titles[page][0]}
        description={titles[page][1]}
        actions={
          page === "account" && (
            <Button icon={<LogOut />} onClick={() => void signOut()}>
              {t("settingsPage.signOut")}
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const msg = useT();
  const [theme, setTheme] = useThemePreference();
  const { me, can } = useAuth();
  const [version, setVersion] = useState<string>();
  const route = parseRoute(usePath());
  const [summary, setSummary] = useState<Summary>();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);

  useEffect(() => {
    void api<{ version: string }>("/api/v1/version").then((v) => setVersion(v.version));
  }, []);

  const call = useApi();
  // The install's other products (OPENASY_PRODUCTS), for the switcher; ids this UI does not know are left out.
  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) =>
        setProducts(
          r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "vulnerabilities" && (PRODUCT_IDS as readonly string[]).includes(p.id)),
        ),
      () => {},
    );
  }, [call]);

  const reload = useCallback(() => void call<Summary>("/api/v1/summary").then(setSummary, () => {}), [call]);
  useEffect(() => {
    reload();
    const t = setInterval(reload, 15_000);
    return () => clearInterval(t);
  }, [reload]);

  const nav = [
    { id: "findings", label: msg("product.findings"), icon: TriangleAlert },
    { id: "hosts", label: msg("product.hosts"), icon: Server, count: summary?.assets.hosts },
    { id: "images", label: msg("product.images"), icon: Boxes, count: summary?.assets.images },
    { id: "exceptions", label: msg("product.exceptions"), icon: ShieldOff },
  ];
  const footerNav = [
    { id: "setup", label: msg("product.setup"), icon: Settings2 },
    ...(can("admin")
      ? [
          { id: "members", label: msg("product.members"), icon: Users },
          { id: "signin", label: msg("product.signIn"), icon: LogIn },
          { id: "tokens", label: msg("product.apiTokens"), icon: KeyRound },
        ]
      : []),
    { id: "account", label: msg("product.account"), icon: UserRound },
  ];
  const active = route.page === "asset" ? undefined : route.page;
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);

  return (
    <AppShell
      product="vulnerabilities"
      nav={nav}
      activeNav={active}
      onNavigate={(id) => navigate(`/${id}`)}
      connectedProducts={products.map((p) => p.id)}
      onSwitchProduct={(id) => {
        const to = products.find((p) => p.id === id);
        if (to) window.location.assign(to.url);
      }}
      footerNav={footerNav}
      user={{ name: me.user.name, role: roleName }}
      theme={theme}
      onThemeChange={setTheme}
    >
      {route.page === "findings" && summary && summary.assets.hosts + summary.assets.images === 0 ? (
        <WelcomePage call={call} feed={summary.feed} reload={reload} version={version} />
      ) : route.page === "findings" ? (
        <FindingsPage call={call} summary={summary} reload={reload} />
      ) : route.page === "hosts" || route.page === "images" ? (
        <AssetsPage key={route.page} call={call} kind={route.page === "hosts" ? "host" : "image"} />
      ) : route.page === "asset" ? (
        <AssetPage key={route.id} call={call} id={route.id} />
      ) : route.page === "exceptions" ? (
        <ExceptionsPage call={call} reload={reload} />
      ) : route.page === "account" || route.page === "members" || route.page === "signin" || route.page === "tokens" ? (
        <SettingsPage page={route.page} />
      ) : (
        <SetupPage call={call} feed={summary?.feed} reload={reload} version={version} />
      )}
    </AppShell>
  );
}

export function App() {
  const [theme] = useThemePreference();
  return (
    // No organization until branding is configurable (ADR 0004); the library's default is a placeholder.
    <BrandProvider theme={theme} brand={{ name: "OpenAsy", organization: undefined }} className="min-h-screen">
      <AuthGate product="OpenAsy Vulnerabilities">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
