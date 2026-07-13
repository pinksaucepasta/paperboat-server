ARG NODE_BASE_IMAGE=node:24-bookworm-slim@sha256:cb4e8f7c443347358b7875e717c29e27bf9befc8f5a26cf18af3c3dec80e58c5
ARG GO_BASE_IMAGE=golang:1.25-bookworm@sha256:a9c020ee3d1508c7be5435c262434e3d3fc1d0e76a11afeb9ddae7d60bc86aa4

FROM ${NODE_BASE_IMAGE} AS papercode

WORKDIR /opt/papercode
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*
RUN corepack enable
COPY papercode/package.json papercode/pnpm-lock.yaml papercode/pnpm-workspace.yaml ./
COPY papercode/tsconfig.base.json papercode/vite.config.ts ./
COPY papercode/patches ./patches
COPY papercode/apps ./apps
COPY papercode/packages ./packages
COPY papercode/scripts ./scripts
COPY papercode/oxlint-plugin-t3code ./oxlint-plugin-t3code
RUN pnpm install --frozen-lockfile
COPY papercode/assets ./assets
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
RUN pnpm run build
RUN pnpm --filter t3 deploy --prod --legacy /opt/papercode-server

FROM ${GO_BASE_IMAGE} AS agentunnel

WORKDIR /src/agentunnel
COPY agentunnel/go.mod agentunnel/go.sum ./
RUN go mod download
COPY agentunnel ./
RUN go build -o /out/agentunnel ./cmd/agentunnel

FROM ${GO_BASE_IMAGE} AS paperboat-server-tools

WORKDIR /src/paperboat-server
COPY paperboat-server/go.mod paperboat-server/go.sum ./
RUN go mod download
COPY paperboat-server ./
RUN go build -o /out/paperboat-activity-reporter-go ./cmd/paperboat-activity-reporter \
  && go build -o /out/paperboat-config-sync ./cmd/paperboat-config-sync

FROM ${NODE_BASE_IMAGE}

ARG NODE_BASE_IMAGE
ARG GO_BASE_IMAGE
ARG PAPERCODE_REVISION
ARG AGENTUNNEL_REVISION
ARG PAPERBOAT_SERVER_REVISION
LABEL org.opencontainers.image.source="https://github.com/pinksaucepasta/paperboat-server" \
  io.paperboat.base.node="${NODE_BASE_IMAGE}" \
  io.paperboat.base.go="${GO_BASE_IMAGE}" \
  io.paperboat.source.papercode.revision="${PAPERCODE_REVISION}" \
  io.paperboat.source.agentunnel.revision="${AGENTUNNEL_REVISION}" \
  io.paperboat.source.server.revision="${PAPERBOAT_SERVER_REVISION}"

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl git openssh-client tini bzip2 xz-utils \
  && rm -rf /var/lib/apt/lists/* \
  && node --version \
  && npm --version

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
COPY --from=paperboat-server-tools /out/paperboat-config-sync /usr/local/bin/paperboat-config-sync
COPY paperboat-server/deploy/project-vm/presets.d/ /etc/paperboat/presets.d/

RUN chmod +x /usr/local/bin/paperboat-* /etc/paperboat/presets.d/*.sh \
  && install -m 0644 /usr/local/bin/paperboat-workspace-cd.sh /etc/profile.d/50-paperboat-workspace.sh \
  && printf '\n# Paperboat: open interactive shells inside the project repository.\n. /etc/profile.d/50-paperboat-workspace.sh\n' >> /etc/bash.bashrc \
  && printf 'export PATH="$HOME/.local/bin:$PATH"\n' > /etc/profile.d/40-paperboat-local-bin.sh

WORKDIR /workspace
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=6 CMD ["/usr/local/bin/paperboat-healthcheck"]
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/paperboat-entrypoint"]
