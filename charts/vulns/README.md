# vulns Helm chart

[OpenAsy Vulnerabilities](https://github.com/openasy/vulns) on Kubernetes: vulns (API, web UI and Grype) as one pod
with its volume, and [vulns-agent](https://github.com/openasy/vulns-agent) on every node as a DaemonSet. The chart has
the same version as the product and its agent.

```bash
helm install vulns oci://ghcr.io/openasy/charts/vulns --version 0.2.0 --namespace openasy --create-namespace
helm test vulns -n openasy
kubectl -n openasy port-forward svc/vulns 8080:8080   # then http://127.0.0.1:8080
kubectl -n openasy get secret vulns -o jsonpath='{.data.VULNS_ADMIN_TOKEN}' | base64 -d; echo
```

This release has no sign-in yet: use it only for testing.

## What it creates

| Resource | |
| --- | --- |
| Deployment `vulns` | One replica, `Recreate`: one process owns the SQLite file, never two (ADR 0011, 0018) |
| PersistentVolumeClaim `vulns-data` | 10 GB: SQLite, SBOMs and the vulnerability data (3 GB unpacked). Kept when the release is deleted |
| Service `vulns` | `http` 8080 for the UI and API, `metrics` 9090 for Prometheus |
| Secret `vulns` | `VULNS_ADMIN_TOKEN` and `VULNS_INGEST_TOKEN`, generated once and kept across upgrades, unless you bring your own |
| DaemonSet `vulns-agent` | On every node, control plane included. Mounts the node's `/` read-only and reports it under its node name |
| Ingress, ServiceMonitor and PodMonitor, NetworkPolicy | Optional |

## Security

- vulns meets the Pod Security `restricted` level: non-root, read-only root filesystem, no capabilities,
  `RuntimeDefault` seccomp, no service account token.
- vulns-agent runs the same way, but mounts the node's `/` through `hostPath` (read-only, recursively where the runtime
  supports it), which the `baseline` and `restricted` levels forbid. Allow it for the namespace:
  `kubectl label namespace openasy pod-security.kubernetes.io/enforce=privileged`. Clusters that forbid `hostPath`
  entirely, such as GKE Autopilot, cannot run the agent: set `agent.enabled=false` and send SBOMs from CI.
- The agent needs nothing from the Kubernetes API and accepts no connections from vulns (ADR 0022, 0023).
- `/metrics` is served on its own port, which the Ingress does not route (ADR 0026). TLS ends at the Ingress.

## Common values

| Value | Default | |
| --- | --- | --- |
| `auth.existingSecret` | | A Secret with `VULNS_ADMIN_TOKEN` and `VULNS_INGEST_TOKEN` you manage |
| `vulns.enabled` | `true` | `false` installs only the agents (needs `agent.url` and `auth.ingestToken`) |
| `vulns.image.digest` | | Pin the image you verified with cosign |
| `vulns.feedUpdateHours` | `24` | `0` turns downloads off for air-gapped clusters; import the data with `PUT /api/v1/feed` |
| `vulns.feedUrl` | | A mirror of `https://grype.anchore.io/databases` |
| `vulns.persistence.size` | `10Gi` | |
| `vulns.ingress.enabled` | `false` | With `host`, `className`, `annotations` and `tlsSecretName` |
| `agent.enabled` | `true` | |
| `agent.url` | this release's vulns | Where the agents report |
| `agent.scanHours` | `6` | |
| `agent.scanExclude` | `[]` | More paths to skip on the nodes |
| `metrics.serviceMonitor.enabled` | `false` | For the Prometheus Operator |
| `networkPolicy.enabled` | `false` | Only agents, `networkPolicy.ingressNamespaces` and Prometheus reach vulns |

Every value is documented in [`values.yaml`](./values.yaml).

## Agents only

For a cluster whose nodes should report to a vulns that runs elsewhere, for example with Docker Compose:

```bash
helm install vulns-agent oci://ghcr.io/openasy/charts/vulns --version 0.2.0 --namespace openasy --create-namespace \
  --set vulns.enabled=false --set agent.url=https://vulns.example.com --set auth.ingestToken=$VULNS_INGEST_TOKEN
```

## Upgrade

```bash
helm upgrade vulns oci://ghcr.io/openasy/charts/vulns --version <new> -n openasy --reset-then-reuse-values
```

Use `--reset-then-reuse-values`: plain `--reuse-values` keeps your values but does not pick up options added in the new
chart. Upgrades are forward-only (ADR 0010); vulns migrates its database on start.

## Verify

```bash
cosign verify ghcr.io/openasy/charts/vulns:0.2.0 \
  --certificate-identity-regexp '^https://github.com/openasy/vulns/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
