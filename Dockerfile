# syntax=docker/dockerfile:1

# Build: the same static binary the Makefile produces for systemd hosts.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH
# Tests run in the build so a broken image is never published. Set
# --build-arg SKIP_TESTS=1 for a quick local iteration.
ARG SKIP_TESTS=0
RUN if [ "$SKIP_TESTS" != "1" ]; then go test ./...; fi
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' \
    -o /out/codboz-online-server ./cmd/codboz-online-server

# Runtime: no shell, no package manager, non-root.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/codboz-online-server /usr/local/bin/codboz-online-server

# Accounts live here; mount it so they survive container updates.
ENV CODBOZ_DATA_DIR=/data \
    CODBOZ_TCP_LISTEN=0.0.0.0:3074 \
    CODBOZ_UDP_LISTEN=0.0.0.0:3478
VOLUME ["/data"]

EXPOSE 3074/tcp 3478/udp

# CODBOZ_STUN_ADDRESS must be set: "auto" for a LAN server, or PUBLIC_IP:3478
# for a server reached through port forwarding. Run with host networking --
# see docs/docker.md for why bridge networking breaks peer-to-peer play.
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/codboz-online-server", "--healthcheck"]
ENTRYPOINT ["/usr/local/bin/codboz-online-server"]
