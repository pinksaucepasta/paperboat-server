FROM node:24-bookworm-slim AS papercode

WORKDIR /opt/papercode
RUN corepack enable
COPY papercode/package.json papercode/pnpm-lock.yaml papercode/pnpm-workspace.yaml ./
COPY papercode/apps ./apps
COPY papercode/packages ./packages
COPY papercode/scripts ./scripts
COPY papercode/oxlint-plugin-t3code ./oxlint-plugin-t3code
RUN pnpm install --frozen-lockfile
RUN pnpm run build
RUN pnpm --filter t3 deploy --prod /opt/papercode-server

FROM golang:1.25-bookworm AS agentunnel

WORKDIR /src/agentunnel
COPY agentunnel/go.mod agentunnel/go.sum ./
RUN go mod download
COPY agentunnel ./
RUN go build -o /out/agentunnel ./cmd/agentunnel

FROM node:24-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl git openssh-client tini \
  && rm -rf /var/lib/apt/lists/*

ENV PAPERBOAT_WORKSPACE=/workspace \
  PAPERBOAT_RUNTIME_DIR=/var/lib/paperboat \
  PAPERBOAT_LOG_DIR=/var/log/paperboat \
  PAPERBOAT_PAPERCODE_LOCAL_URL=http://127.0.0.1:4099 \
  PAPERBOAT_PAPERCODE_BASE_DIR=/workspace/.paperboat/papercode \
  PAPERBOAT_PAPERCODE_COMMAND=/usr/local/bin/paperboat-start-papercode \
  PAPERBOAT_AGENTUNNEL_COMMAND=/usr/local/bin/paperboat-start-agentunnel \
  PAPERBOAT_CONFIG_SYNC_COMMAND=/usr/local/bin/paperboat-config-sync \
  PAPERBOAT_PRESET_APPLY_COMMAND=/usr/local/bin/paperboat-apply-presets \
  PAPERBOAT_ACTIVITY_COMMAND=/usr/local/bin/paperboat-activity-reporter

COPY --from=papercode /opt/papercode-server /opt/papercode-server
COPY --from=agentunnel /out/agentunnel /usr/local/bin/agentunnel
COPY paperboat-server/deploy/project-vm/bin/ /usr/local/bin/

RUN chmod +x /usr/local/bin/paperboat-*

WORKDIR /workspace
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=6 CMD ["/usr/local/bin/paperboat-healthcheck"]
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/paperboat-entrypoint"]
