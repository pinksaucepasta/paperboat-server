FROM golang:1.25.7-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/paperboat-server ./cmd/paperboat-server
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/paperboat-activity-reporter ./cmd/paperboat-activity-reporter

FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl tini \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /out/paperboat-server /usr/local/bin/paperboat-server
COPY --from=build /out/paperboat-activity-reporter /usr/local/bin/paperboat-activity-reporter

EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/paperboat-server", "serve"]
