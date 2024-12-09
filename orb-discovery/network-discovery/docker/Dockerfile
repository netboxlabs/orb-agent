ARG GO_VERSION=1.23

FROM golang:${GO_VERSION}-alpine AS builder


WORKDIR /src

COPY . .

WORKDIR /src/network-discovery   

RUN apk update && apk add --no-cache build-base make git

RUN make bin

FROM alpine:3.20

RUN apk update && apk add --no-cache nmap

COPY --from=builder /src/network-discovery/build/network-discovery /usr/local/bin/network-discovery

LABEL maintainer="techops@netboxlabs.com"
LABEL org.opencontainers.image.title="Orb Network Discovery"
LABEL org.opencontainers.image.url="https://github.com/netboxlabs/orb-discovery/tree/develop/network-discovery"
LABEL org.opencontainers.image.documentation="https://github.com/netboxlabs/orb-discovery/tree/develop/network-discovery"
LABEL org.opencontainers.image.description="NetBox Labs network-discovery image"
LABEL org.opencontainers.image.vendor="NetBox Labs, Inc"
LABEL org.opencontainers.image.authors="techops@netboxlabs.com"
LABEL org.opencontainers.image.licenses="Apache-2.0"

CMD ["/usr/local/bin/network-discovery"]
