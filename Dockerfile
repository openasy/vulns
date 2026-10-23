# syntax=docker/dockerfile:1

# Grype matches SBOMs against vulnerability data. Pinned by digest (ADR 0027); Dependabot proposes updates.
FROM anchore/grype:v0.121.0@sha256:621d56d1d68106b787022c81546f7e0a36202a25d1239f0c20195fab8c16f7ea AS grype

FROM node:26.12.0-trixie-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build && npm prune --omit=dev && mkdir -p /out/data/grype /out/data/tmp

# Node runs the TypeScript sources directly; only production dependencies are copied.
FROM gcr.io/distroless/nodejs26-debian13:nonroot
WORKDIR /app
COPY --from=grype /grype /usr/local/bin/grype
COPY --from=build /app/package.json /app/openapi.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/server ./server
COPY --from=build /app/dist/web ./dist/web
COPY --from=build /app/dist/docs ./dist/docs
COPY --from=build --chown=nonroot:nonroot /out/data /data
# Everything that is written goes to /data, so the root filesystem can be read-only (ADR 0022).
ENV NODE_ENV=production PORT=8080 VULNS_DB=/data/vulns.db VULNS_FEED_DIR=/data/grype TMPDIR=/data/tmp
VOLUME /data
EXPOSE 8080
USER nonroot
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:8080/healthz').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["server/main.ts"]
