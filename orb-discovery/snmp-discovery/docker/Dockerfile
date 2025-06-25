ARG GO_VERSION=1.24

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

WORKDIR /src/snmp-discovery

COPY .. .

ARG TARGETOS TARGETARCH

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /build/snmp-discovery ./cmd/main.go

FROM alpine:3.22

# Copy the binary
COPY --from=builder /build/snmp-discovery /usr/local/bin/snmp-discovery

LABEL maintainer="techops@netboxlabs.com"
LABEL org.opencontainers.image.title="Orb SNMP Discovery"
LABEL org.opencontainers.image.url="https://github.com/netboxlabs/orb-discovery/tree/release/snmp-discovery"
LABEL org.opencontainers.image.documentation="https://github.com/netboxlabs/orb-discovery/tree/release/snmp-discovery"
LABEL org.opencontainers.image.description="NetBox Labs snmp-discovery image"
LABEL org.opencontainers.image.vendor="NetBox Labs, Inc"
LABEL org.opencontainers.image.authors="techops@netboxlabs.com"
LABEL org.opencontainers.image.licenses="Apache-2.0"

CMD ["/usr/local/bin/snmp-discovery"]