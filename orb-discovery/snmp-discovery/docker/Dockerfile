ARG GO_VERSION=1.23

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

RUN apk update && apk add --no-cache build-base make git

WORKDIR /src/snmp-discovery

COPY . .

ARG TARGETOS TARGETARCH

RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /build/snmp-discovery ./cmd/main.go

FROM alpine:3.20

RUN apk update && apk add --no-cache nmap

COPY --from=builder /build/snmp-discovery /usr/local/bin/snmp-discovery

LABEL maintainer="techops@netboxlabs.com"
LABEL org.opencontainers.image.title="Orb snmp Discovery"
LABEL org.opencontainers.image.url="https://github.com/netboxlabs/orb-discovery/tree/develop/snmp-discovery"
LABEL org.opencontainers.image.documentation="https://github.com/netboxlabs/orb-discovery/tree/develop/snmp-discovery"
LABEL org.opencontainers.image.description="NetBox Labs snmp-discovery image"
LABEL org.opencontainers.image.vendor="NetBox Labs, Inc"
LABEL org.opencontainers.image.authors="techops@netboxlabs.com"
LABEL org.opencontainers.image.licenses="Apache-2.0"

CMD ["/usr/local/bin/snmp-discovery"]