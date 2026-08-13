ARG PAPERBOAT_VERSION

FROM golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS build
ARG PAPERBOAT_VERSION

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN printf '%s\n' "${PAPERBOAT_VERSION}" | grep -Eq '^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.(0|[1-9][0-9]*)$' \
  && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/paperboat-server ./cmd/paperboat-server

FROM debian:bookworm-slim

ARG PAPERBOAT_VERSION
LABEL org.opencontainers.image.version="${PAPERBOAT_VERSION}"

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl tini \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /out/paperboat-server /usr/local/bin/paperboat-server

EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/paperboat-server", "serve"]
