# vulns

[![CI](https://github.com/openasy/vulns/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/vulns/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/openasy/vulns?sort=semver)](https://github.com/openasy/vulns/releases)
[![Image](https://img.shields.io/badge/ghcr.io-openasy%2Fvulns-2496ED?logo=docker&logoColor=white)](https://github.com/openasy/vulns/pkgs/container/vulns)
[![Signed with cosign](https://img.shields.io/badge/image-signed%20with%20cosign-2a6db2)](#verify-an-image)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) Vulnerabilities product: OS package and container image vulnerabilities,
ranked by exploitability. API, web UI and matching in one container with one version. Hosts report through the
separate [vulns-agent](https://github.com/openasy/vulns-agent); images are sent from CI.

People sign in with an account (password plus authenticator app or passkey), with a passkey alone, or through your
identity provider (OIDC). Each person has a role in this vulns; scripts and CI use API tokens. See [Sign-in](#sign-in).

## How it works

```
host ── vulns-agent (Syft, read-only /host) ──┐
                                               ├─ SBOM ──▶ vulns ── Grype + vulnerability data ──▶ findings
CI ──── syft <image> | curl ──────────────────┘
```

- Everything arrives as an SBOM (Syft JSON, CycloneDX JSON or SPDX JSON). vulns keeps the last SBOM of each host and
  image, so when the vulnerability data changes every asset is matched again without scanning it again.
- Matching uses [Grype](https://github.com/anchore/grype) and its vulnerability data: distribution advisories (Debian,
  Ubuntu, RHEL, Alpine, Amazon Linux, SUSE and more), GitHub advisories, NVD, the CISA Known Exploited Vulnerabilities
  catalogue and EPSS. Lists put known exploited vulnerabilities first, then Grype's risk score (severity and EPSS).
- Findings are grouped by vulnerability and source package (glibc rather than libc6 and libc-bin), with how many hosts
  and images have it and the version that fixes it. Findings that stop matching are resolved and kept as history.
- Exceptions accept a risk on one asset or on all of them, with a reason and an expiry within a year.
- Nothing logs in to your hosts. The agent reads package databases through a read-only mount as an unprivileged user,
  accepts no connections and only sends the SBOM (ADR 0022, 0023). There are no SSH keys to protect.

Why Grype and Syft, and not Vuls: see [Engine](#engine).

## Run

```bash
export VULNS_INGEST_TOKEN=$(openssl rand -hex 32)
openssl rand -hex 32 > openasy-kek
docker compose up -d
docker compose logs vulns | grep 'no owner yet'
```

[`compose.yaml`](./compose.yaml) starts `ghcr.io/openasy/vulns` and a `ghcr.io/openasy/vulns-agent` for this host.
Open the link from the log once to create the owner account; there is no default password (ADR 0013). The UI and API
are on http://localhost:8080; the API reference with *Try it out* is at http://localhost:8080/api/docs/.
On first start vulns downloads the vulnerability data (about 200 MB, 3 GB unpacked on the volume): give `/data` at
least 8 GB. SBOMs sent before it arrives are kept and matched as soon as it does.

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `VULNS_PUBLIC_URL` | `http://localhost:8080` | The address people open, with `https://` behind your TLS proxy. Cookies, passkeys and OIDC redirects use it |
| `OPENASY_PRODUCTS` | | The install's other OpenAsy products, for the product switcher: `identity=https://id.example.com,infrastructure=https://infra.example.com`. Give every product the same value |
| `OPENASY_HOSTS` | | The install's hosts file, shared with Infrastructure and Logs (ADR 0052). The main page lists the servers in it with no scan, matched by name or address in host assets |
| `VULNS_INGEST_TOKEN` | | Token for vulns-agent and CI. It can send SBOMs and heartbeats, nothing else |
| `VULNS_SECRETS_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key that encrypts secrets in the database (ADR 0021). Without it vulns warns and stores them unencrypted |
| `VULNS_PASSWORD_SIGN_IN` | `true` | `false` when everyone signs in through OIDC |
| `OPENASY_OIDC_*` | | Sign-in through your identity provider, the same names in every product, see [Sign-in](#sign-in) |
| `VULNS_ADMIN_TOKEN` | | Deprecated: one shared admin token without an expiry, for scripts from before sign-in. Use an API token |
| `VULNS_FEED_UPDATE_HOURS` | `24` | How often to download newer vulnerability data; `0` turns downloads off |
| `VULNS_FEED_URL` | Grype's | A mirror of `https://grype.anchore.io/databases` |
| `VULNS_RETENTION_DAYS` | `90` | Resolved findings and expired exceptions are deleted after this |
| `VULNS_DB` | `/data/vulns.db` | SQLite file (WAL), on the `/data` volume |
| `VULNS_FEED_DIR` | `/data/grype` | Grype's vulnerability data |
| `VULNS_HEADLESS` | `false` | `true` serves only the API |

| `VULNS_METRICS_PORT` | | Serve `/metrics` on this port only, not on `PORT` (ADR 0026). The Helm chart uses 9090 |

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`; everything it
writes goes to `/data`.

### Sign-in

Sign-in comes from [@openasy/auth](https://github.com/openasy/auth), the same in every OpenAsy product (ADR 0002).

- **Roles** (ADR 0003): viewers see everything; editors also accept risks and request scans; admins also delete
  assets, manage the vulnerability data, members and API tokens; owners also manage owners. Owners and admins who sign
  in with a password must add an authenticator app or a passkey.
- **Members**: admins invite people under Settings → Members. There is no email yet, so the admin sends the one-time
  link. Forgotten passwords work the same way: the admin creates a new link.
- **API tokens**: Settings → API tokens. One role each, an expiry within a year, the secret shown once. Send it as
  `Authorization: Bearer oa_vulns_...`. A token with the editor role can also send SBOMs from CI.
- **Settings, Sign-in**: owners add an identity provider in the UI instead: OpenAsy Identity, Keycloak, Microsoft Entra
  ID, Okta, Google, authentik, ZITADEL or any OpenID Connect provider. The page shows that provider's steps and the
  redirect URI to register, checks the issuer, and maps groups to roles; the client secret is kept encrypted.
- **OIDC** (Entra ID, Okta, Google, Keycloak, Authentik, Zitadel...): register vulns as a confidential client with the
  redirect URI `<VULNS_PUBLIC_URL>/api/v1/auth/oidc/sso/callback`, then set the variables below. Their names are the
  same in every OpenAsy product, so an install sets them once; only the client is this product's:

  | Variable | |
  | --- | --- |
  | `OPENASY_OIDC_ISSUER`, `OPENASY_OIDC_CLIENT_ID`, `OPENASY_OIDC_CLIENT_SECRET` | Required to turn it on |
  | `OPENASY_OIDC_PROVIDER` | `keycloak`, `entra`, `okta`, `google`, `authentik`, `zitadel` or `openasy-identity`: that provider's defaults |
  | `OPENASY_OIDC_NAME` | On the button: "Continue with ...". Default `SSO` |
  | `OPENASY_OIDC_SCOPES` | Default `openid email profile`; add the scope that carries groups |
  | `OPENASY_OIDC_GROUPS_CLAIM` | Default `groups` |
  | `OPENASY_OIDC_ROLE_MAPPING` | `vulns-admins=admin,staff=viewer`: the role follows the groups on every sign-in |
  | `OPENASY_OIDC_DEFAULT_ROLE` | Role for people nobody invited. Unset: only invited people and mapped groups get in |
  | `OPENASY_OIDC_ALLOWED_DOMAINS` | Comma-separated email domains, for providers anyone can join (Google) |
  | `OPENASY_OIDC_AUTO_REDIRECT` | `true`: the sign-in page opens the provider straight away; `?local=1` still shows the form |

  The names before 0.5.0 of `@openasy/auth`, such as `VULNS_OIDC_ISSUER`, still work for now and log a warning.

  An existing member is linked by the email the provider says it has verified. People from the provider use its MFA.

SAML 2.0, LDAP and trusted proxy headers are planned.

### Kubernetes

```bash
helm install vulns oci://ghcr.io/openasy/charts/vulns --version 0.7.0 --namespace openasy --create-namespace
helm test vulns -n openasy
```

The [chart](./charts/vulns) installs vulns as one pod with a 10 GB volume and vulns-agent on every node as a
DaemonSet; nodes appear under Hosts as Kubernetes nodes. vulns always runs as a single replica with the `Recreate`
strategy, because one process owns the SQLite file (ADR 0011, 0018): Kubernetes restarts it elsewhere when a node
fails, but does not run two. Tokens are generated on install and kept across upgrades; `/metrics` is on port 9090,
which the optional Ingress does not expose. See [`values.yaml`](./charts/vulns/values.yaml) for every option
(Ingress with TLS, ServiceMonitor, NetworkPolicy, pinned image digests, air-gapped).

vulns meets the Pod Security `restricted` level. vulns-agent reads each node's `/` through a read-only `hostPath`
mount, which `baseline` and `restricted` forbid: allow it for the namespace with
`kubectl label namespace openasy pod-security.kubernetes.io/enforce=privileged`. The agent itself still runs
unprivileged, without capabilities and with a read-only root filesystem. Clusters that forbid `hostPath` entirely,
such as GKE Autopilot, cannot run the agent: set `agent.enabled=false` there and send SBOMs from CI.

Already running vulns elsewhere, for example with Compose? Install only the agents, and every node reports to it:

```bash
helm install vulns-agent oci://ghcr.io/openasy/charts/vulns --version 0.7.0 --namespace openasy --create-namespace \
  --set vulns.enabled=false --set agent.url=https://vulns.example.com --set auth.ingestToken=$VULNS_INGEST_TOKEN
```

Upgrade with `helm upgrade vulns oci://ghcr.io/openasy/charts/vulns --version <new> -n openasy --reset-then-reuse-values`
(plain `--reuse-values` does not pick up options added in the new chart).

### Hosts

Run [vulns-agent](https://github.com/openasy/vulns-agent) on each host with the host's root mounted read-only:

```bash
docker run -d --name vulns-agent --restart unless-stopped --hostname "$(hostname)" \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -v /:/host:ro -e VULNS_URL=https://vulns.example.com -e VULNS_INGEST_TOKEN=... \
  ghcr.io/openasy/vulns-agent:0.7.0
```

It scans on start and every 6 hours, and when someone clicks *Scan now*. On Kubernetes the chart runs it on every
node instead (see [Kubernetes](#kubernetes)).

Hosts that [Infrastructure](https://github.com/openasy/infra) reads need no agent: give it `INFRA_VULNS_URL` and
`VULNS_INGEST_TOKEN` as `INFRA_VULNS_TOKEN`, and it sends each host's packages as a CycloneDX SBOM when they change.
An SBOM that names no CPEs gets the ones Syft would write, so the findings match a scan with the agent.

### Images

Send an SBOM from CI after each build. With `wait=true` the answer is the matched asset, so the job can fail on it:

```bash
syft "$IMAGE" -o syft-json | curl -sf -X POST -H "Authorization: Bearer $VULNS_INGEST_TOKEN" \
  -H 'content-type: application/json' --data-binary @- \
  "https://vulns.example.com/api/v1/sboms?kind=image&name=$IMAGE&wait=true" > result.json
jq -e '.knownExploited == 0 and .open.critical == 0' result.json
```

### Without internet access

Set `VULNS_FEED_UPDATE_HOURS=0`. On a machine with access, download the data with `grype db download` (or the URL
that `grype db list` prints) and upload it; every asset is matched again (ADR 0015):

```bash
curl -sf -X PUT -H "Authorization: Bearer $VULNS_API_TOKEN" -H 'content-type: application/zstd' \
  --data-binary @vulnerability-db.tar.zst https://vulns.example.com/api/v1/feed
```

vulns makes no other outbound requests: no telemetry, and Grype's own update checks are off. The UI warns when the data
is more than three days old.

## Endpoints

| Path | |
| --- | --- |
| `/healthz`, `/readyz` | Liveness and readiness |
| `/metrics` | Prometheus metrics: assets, open findings by severity, known exploited, age of the data, queue |
| `GET /api/v1/version` | Product and version |
| `GET /api/v1/products` | The other OpenAsy products, from `OPENASY_PRODUCTS` |
| `GET /api/v1/summary` | Counts for the overview |
| `GET /api/v1/vulnerabilities`, `/{id}` | Open vulnerabilities across every asset, most urgent first; where one is |
| `POST /api/v1/sboms?kind=&name=&wait=` | Send an SBOM (ingest token) |
| `/api/v1/assets`, `/{id}`, `/{id}/findings`, `/{id}/sbom`, `/{id}/scan` | Hosts and images, their findings and SBOM; ask an agent to scan |
| `/api/v1/exceptions`, `/{id}` | Accepted risk |
| `GET /api/v1/feed`, `PUT /api/v1/feed`, `POST /api/v1/feed/update` | The vulnerability data: status, import, download |
| `POST /api/v1/agents/heartbeat` | Used by vulns-agent |
| `/api/docs/` | Interactive API reference (Swagger UI), bundled in the image |
| `/api/openapi.json` | OpenAPI 3.1 description |

The description lives in [`openapi.json`](./openapi.json) and is the contract: `server/openapi.test.ts` calls every
operation and fails if a response does not match it. Errors are RFC 9457 Problem Details
(`application/problem+json`) with a stable `code`. Lists are paginated with an opaque `cursor`.

## Engine

We considered [Vuls](https://vuls.io), [Trivy](https://github.com/aquasecurity/trivy) and
[Grype](https://github.com/anchore/grype) with [Syft](https://github.com/anchore/syft), against the design decisions:

| | Vuls | Trivy | Grype + Syft |
| --- | --- | --- | --- |
| Licence | GPL-3.0 | Apache-2.0 | Apache-2.0 |
| Reaching hosts | SSH from the scanner to every host, or its own server mode | Scanner on the host, or SBOM | SBOM from anywhere |
| Vulnerability data | Several separate fetchers and databases (NVD, OVAL, gost, exploit DB) | One BoltDB file | One SQLite file, with KEV and EPSS built in |
| Exploitability ranking | Exploit DB and KEV via extra fetchers | KEV, no EPSS | KEV, EPSS and a risk score per match |
| Air-gapped | Run every fetcher offline | Download the DB as an OCI artifact | `grype db download` / `import` |

- Agentless SSH scanning would put keys to every host in one product, which a compromised product could then use;
  ADR 0022 asks for the opposite. With SBOMs nothing reaches into hosts.
- One SQLite file of data fits ADR 0011 and 0028 better than several fetch services.
- Trivy is a good scanner too, but its project and releases were compromised in March 2026 (CVE-2026-33634), and it
  has no EPSS. Grype and Syft are pinned by digest in our images and updated by Dependabot after review (ADR 0027).

Grype and Syft are separate programs run as child processes with fixed arguments; they are not linked into this code.

## Resources

Measured on 0.1.0: about 80 MB of memory at idle; matching a Debian 12 image (88 packages, 361 findings) takes about
4 seconds and stays under 400 MB. The image is 375 MB, over ADR 0028's 300 MB, because the Grype binary is about
110 MB. The vulnerability data takes 3 GB on the volume.

## Upgrade

### To 0.3.0

- The sign-in variables lose the `VULNS_` prefix and have the same names in every product (ADR 0002):
  `VULNS_OIDC_ISSUER` is now `OPENASY_OIDC_ISSUER`, and so on for every `VULNS_OIDC_*`. The old names still work, with
  a warning in the log, and go in a later release: rename them, in `vulns.extraEnv` with the chart.
- Upgrade vulns-agent to the same version.

## Verify an image

Images are signed with cosign (keyless), carry an SPDX SBOM attestation and SLSA level 3 provenance.

```bash
cosign verify ghcr.io/openasy/vulns:0.7.0 \
  --certificate-identity-regexp '^https://github.com/openasy/vulns/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
slsa-verifier verify-image ghcr.io/openasy/vulns@sha256:<digest> --source-uri github.com/openasy/vulns
```

## Develop

```bash
npm ci
npm start      # API on :8080; needs grype on PATH (VULNS_GRYPE_BIN) and VULNS_DB=./data/vulns.db VULNS_FEED_DIR=./data/grype TMPDIR=./data/tmp
npm run dev    # web UI on :5173, proxies /api
npm run typecheck && npm test
e2e/run.sh     # needs Docker and the vulns:dev and vulns-agent:dev images; GRYPE_DB_DIR=<dir> reuses downloaded data
helm lint charts/vulns
```

CI also installs the chart on a [kind](https://kind.sigs.k8s.io/) cluster with the images it built, waits for every
node to be scanned, runs `helm test` and checks that an upgrade keeps the tokens. To do the same locally:

```bash
kind create cluster --name vulns && kind load docker-image vulns:dev vulns-agent:dev --name vulns
helm install vulns charts/vulns -n openasy --create-namespace --wait \
  --set vulns.image.repository=vulns,vulns.image.tag=dev,vulns.image.pullPolicy=Never \
  --set agent.image.repository=vulns-agent,agent.image.tag=dev,agent.image.pullPolicy=Never
helm test vulns -n openasy --logs
```

Node runs the TypeScript sources in `server/` directly; there is no build step for the server. Tests replace Grype with
a stand-in that answers with real Grype output (`server/fixtures`); `e2e/run.sh` uses the real one.

## Release

1. Set the version in `package.json`, `openapi.json` and `charts/vulns/Chart.yaml` (`version` and `appVersion`), merge
   to `main`. The release refuses a tag that does not match all of them.
2. Push the tag: `git tag v0.1.0 && git push origin v0.1.0`.
3. GitHub Actions tests, builds `linux/amd64` and `linux/arm64`, pushes `ghcr.io/openasy/vulns:0.1.0` and `:0.1`
   (never `latest`), signs it, attaches the SBOM and provenance, pushes the chart to `oci://ghcr.io/openasy/charts/vulns`
   and signs it, and creates the GitHub release.
4. Release vulns-agent with the same version.

## Design decisions

See [openasy.github.io/principles](https://openasy.github.io/principles) and the records in [openasy.github.io `docs/decisions`](https://github.com/openasy/openasy.github.io/tree/main/docs/decisions).

## Licence

[AGPL-3.0](./LICENSE). You may use, change and share it; if you run a changed version for others, including as a
hosted service, you must offer them your source code under the same licence ([ADR 0008](https://github.com/openasy/openasy.github.io/blob/main/docs/decisions/0008-open-source.md)).
"OpenAsy" and its logo are trademarks and are not covered by the licence. Grype and Syft are Apache-2.0, by Anchore.
