# syntax=docker/dockerfile:1

FROM golang:1.26.2-bookworm AS build

ARG VERSION=2.0.0-beta.3

ENV GOWORK=off

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X=flexconnect/internal/buildinfo.Version=${VERSION}" -o /out/flexconnectd ./cmd/flexconnectd
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X=flexconnect/internal/buildinfo.Version=${VERSION}" -o /out/flexconnect ./cmd/flexconnect

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dnsutils \
        iproute2 \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/flexconnectd /usr/local/bin/flexconnectd
COPY --from=build /out/flexconnect /usr/local/bin/flexconnect

ENV FLEXCONNECT_SOCKET=/run/flexconnect/flexconnect.sock \
    FLEXCONNECT_STATE=/var/lib/flexconnect/state.json \
    FLEXCONNECT_SECRET_STORE=memory \
    FLEXCONNECT_CONNECT_ON_START=true \
    FLEXCONNECT_PROFILE_NAME=docker \
    FLEXCONNECT_AUTO_RECONNECT=true \
    FLEXCONNECT_SOCKS5_ENABLED=true \
    FLEXCONNECT_SOCKS5_LISTEN=0.0.0.0:1080

VOLUME ["/var/lib/flexconnect"]
EXPOSE 1080/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/flexconnect", "--socket", "/run/flexconnect/flexconnect.sock", "status", "--json"]

ENTRYPOINT ["/usr/local/bin/flexconnectd"]
