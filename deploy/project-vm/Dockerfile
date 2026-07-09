# PAPERCODE selects whether the papercode server is baked into the image:
#   enabled  (default) — requires the papercode repo in the build context
#   disabled           — runtime boots with PAPERBOAT_PAPERCODE_MODE=disabled
ARG PAPERCODE=enabled

FROM node:24-bookworm-slim AS papercode-enabled

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

FROM node:24-bookworm-slim AS papercode-disabled
RUN mkdir -p /opt/papercode-server

FROM papercode-${PAPERCODE} AS papercode

FROM golang:1.25-bookworm AS agentunnel

WORKDIR /src/agentunnel
COPY agentunnel/go.mod agentunnel/go.sum ./
RUN go mod download
COPY agentunnel ./
RUN go build -o /out/agentunnel ./cmd/agentunnel

FROM golang:1.25-bookworm AS paperboat-server-tools

WORKDIR /src/paperboat-server
COPY paperboat-server/go.mod paperboat-server/go.sum ./
RUN go mod download
COPY paperboat-server ./
RUN go build -o /out/paperboat-activity-reporter-go ./cmd/paperboat-activity-reporter

FROM node:24-bookworm-slim

ARG PAPERCODE=enabled
ENV PAPERBOAT_PAPERCODE_MODE=${PAPERCODE}

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl git openssh-client tini bzip2 xz-utils \
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
COPY --from=paperboat-server-tools /out/paperboat-activity-reporter-go /usr/local/bin/paperboat-activity-reporter-go
COPY paperboat-server/deploy/project-vm/bin/ /usr/local/bin/
COPY paperboat-server/deploy/project-vm/presets.d/ /etc/paperboat/presets.d/

RUN chmod +x /usr/local/bin/paperboat-* /etc/paperboat/presets.d/*.sh \
  && install -m 0644 /usr/local/bin/paperboat-workspace-cd.sh /etc/profile.d/50-paperboat-workspace.sh \
  && printf '\n# Paperboat: open interactive shells inside the project repository.\n. /etc/profile.d/50-paperboat-workspace.sh\n' >> /etc/bash.bashrc \
  && printf 'export PATH="$HOME/.local/bin:$PATH"\n' > /etc/profile.d/40-paperboat-local-bin.sh

WORKDIR /workspace
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=6 CMD ["/usr/local/bin/paperboat-healthcheck"]
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/paperboat-entrypoint"]
