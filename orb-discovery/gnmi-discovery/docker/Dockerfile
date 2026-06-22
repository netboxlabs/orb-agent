ARG GO_VERSION=1.26.4

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

WORKDIR /src/gnmi-discovery

COPY . .

ARG TARGETOS TARGETARCH

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -trimpath -o /build/gnmi-discovery ./cmd/main.go

FROM alpine:3.23

# Copy the binary
COPY --from=builder /build/gnmi-discovery /usr/local/bin/gnmi-discovery

# Copy the bundled profiles as an operator reference of the embedded set.
# Profiles are compiled into the binary via go:embed; this layer is for
# inspection and opt-in override mounting (-profiles-dir). An empty
# -profiles-dir (the default) means embedded-only; no default is set here.
COPY mapping/gnmi-profiles /usr/local/share/gnmi-profiles

LABEL maintainer="techops@netboxlabs.com"
LABEL org.opencontainers.image.title="Orb gNMI Discovery"
LABEL org.opencontainers.image.url="https://github.com/netboxlabs/orb-agent/tree/release/orb-discovery/gnmi-discovery"
LABEL org.opencontainers.image.documentation="https://github.com/netboxlabs/orb-agent/tree/release/orb-discovery/gnmi-discovery"
LABEL org.opencontainers.image.description="NetBox Labs gnmi-discovery image"
LABEL org.opencontainers.image.vendor="NetBox Labs, Inc"
LABEL org.opencontainers.image.authors="techops@netboxlabs.com"
LABEL org.opencontainers.image.licenses="Apache-2.0"

CMD ["/usr/local/bin/gnmi-discovery"]
