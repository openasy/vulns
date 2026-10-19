#!/bin/bash
# End-to-end: vulns-agent scans a host root with Syft, vulns matches it with Grype and real vulnerability data,
# an image SBOM from "CI" is matched with ?wait=true, an exception hides a finding, and a rescan request reaches the agent.
# Needs Docker and the vulns:dev and vulns-agent:dev images. Downloads the vulnerability data (about 200 MB)
# unless GRYPE_DB_DIR points at a directory that already holds it (the one with 6/vulnerability.db).
set -u
FAIL=0
fail() { echo "FAIL: $*"; FAIL=1; }
A="Authorization: Bearer admin-e2e"
api() { curl -s -H "$A" -H "content-type: application/json" "$@"; }
jsonq() { node -pe "const d=JSON.parse(require('fs').readFileSync(0)); $1"; }
D=$(mktemp -d)
cleanup() { docker rm -f e2e-vulns e2e-agent >/dev/null 2>&1; docker network rm e2e-vulns >/dev/null 2>&1; docker volume rm e2e-vulns-data >/dev/null 2>&1; rm -rf "$D"; }
cleanup
D=$(mktemp -d)
docker network create e2e-vulns >/dev/null

# The "host": an Ubuntu 24.04 root filesystem, mounted read-only like / on a real host.
cid=$(docker create ubuntu:24.04) && docker export "$cid" | tar -x -C "$D" 2>/dev/null; docker rm "$cid" >/dev/null
HOST_ROOT="$D"

FEED=(-e VULNS_FEED_UPDATE_HOURS=24)
[ -n "${GRYPE_DB_DIR:-}" ] && FEED=(-e VULNS_FEED_UPDATE_HOURS=0 -v "$GRYPE_DB_DIR:/data/grype")
docker run -d --name e2e-vulns --network e2e-vulns -p 18096:8080 --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v e2e-vulns-data:/data "${FEED[@]}" -e VULNS_ADMIN_TOKEN=admin-e2e -e VULNS_INGEST_TOKEN=ingest-e2e vulns:dev >/dev/null
for _ in $(seq 1 30); do curl -sf localhost:18096/readyz >/dev/null && break; sleep 0.5; done

echo "--- vulnerability data"
for _ in $(seq 1 600); do built=$(api localhost:18096/api/v1/feed | jsonq 'd.built ?? ""'); [ -n "$built" ] && break; sleep 1; done
echo "built: ${built:-none}"
[ -n "$built" ] || fail "no vulnerability data after 10 minutes: $(api localhost:18096/api/v1/feed)"

echo "--- an image SBOM from CI, waiting for the result"
docker run --rm anchore/syft:v1.55.0 debian:12.0 -o syft-json -q > "$D-image.json"
curl -s -X POST -H "Authorization: Bearer ingest-e2e" -H 'content-type: application/json' --data-binary @"$D-image.json" \
  "localhost:18096/api/v1/sboms?kind=image&name=debian:12.0&wait=true" > "$D-result.json"
echo "image: $(jsonq '`${d.match.status}, ${d.open.critical} critical, ${d.open.high} high, ${d.knownExploited} known exploited`' < "$D-result.json")"
[ "$(jsonq d.match.status < "$D-result.json")" = done ] || fail "the image was not matched"
[ "$(jsonq 'd.knownExploited > 0' < "$D-result.json")" = true ] || fail "debian:12.0 should have known exploited vulnerabilities (CVE-2023-4911)"
IMAGE=$(jsonq d.id < "$D-result.json")

echo "--- a host through vulns-agent"
docker run -d --name e2e-agent --network e2e-vulns --hostname e2e-host --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -v "$HOST_ROOT:/host:ro" -e VULNS_URL=http://e2e-vulns:8080 -e VULNS_INGEST_TOKEN=ingest-e2e -e HEARTBEAT_SECONDS=2 vulns-agent:dev >/dev/null
host() { api "localhost:18096/api/v1/assets?kind=host" | jsonq "JSON.stringify(d.assets.find(a=>a.name==='e2e-host')??null)"; }
for _ in $(seq 1 90); do [ "$(host | jsonq 'd?.match.status ?? ""')" = done ] && break; sleep 1; done
echo "host: $(host | jsonq '`${d?.distro}, ${d?.packages} packages, ${d?.match.status}, agent ${d?.agent?.version}`')"
[ "$(host | jsonq 'd?.distro')" = "ubuntu 24.04" ] || fail "the host's distribution was not detected"
[ "$(host | jsonq 'd.packages > 50')" = true ] || fail "the agent sent too few packages"
HOST=$(host | jsonq d.id)

echo "--- ask the agent for a scan"
before=$(docker logs e2e-agent 2>&1 | grep -c '"scan sent"')
api -X POST "localhost:18096/api/v1/assets/$HOST/scan" >/dev/null
for _ in $(seq 1 20); do [ "$(docker logs e2e-agent 2>&1 | grep -c '"scan sent"')" -gt "$before" ] && break; sleep 1; done
[ "$(docker logs e2e-agent 2>&1 | grep -c '"scan sent"')" -gt "$before" ] || fail "the agent did not scan when asked"
echo "scans sent: $(docker logs e2e-agent 2>&1 | grep -c '"scan sent"')"

echo "--- exceptions"
kev() { api "localhost:18096/api/v1/vulnerabilities?kev=true&asset=$IMAGE" | jsonq 'd.vulnerabilities.length'; }
first=$(api "localhost:18096/api/v1/vulnerabilities?kev=true&asset=$IMAGE&limit=1" | jsonq 'd.vulnerabilities[0].vulnerability')
n=$(kev)
until=$(node -pe 'new Date(Date.now()+86400000*30).toISOString()')
api -X POST localhost:18096/api/v1/exceptions -d "{\"vulnerability\":\"$first\",\"assetId\":\"$IMAGE\",\"reason\":\"e2e: accepted\",\"expiresAt\":\"$until\"}" >/dev/null
echo "known exploited on the image: $n, after accepting $first: $(kev)"
[ "$(kev)" -lt "$n" ] || fail "the exception did not hide $first"

echo "--- the agent is unprivileged and the product's root filesystem is read-only"
[ "$(docker inspect -f '{{.Config.User}}' e2e-agent)" = nonroot ] || fail "the agent runs as root"
docker exec e2e-vulns /nodejs/bin/node -e "require('fs').writeFileSync('/app/x','x')" >/dev/null 2>&1 && fail "the product could write to its root filesystem"

[ "${KEEP:-}" = "1" ] || cleanup
rm -rf "$D-image.json" "$D-result.json"
[ "$FAIL" = 0 ] && echo "e2e: all checks passed"
exit $FAIL
