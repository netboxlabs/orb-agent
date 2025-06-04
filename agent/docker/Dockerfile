ARG PKTVISOR_TAG=develop
ARG OTEL_TAG=develop
ARG NETWORK_DISCOVERY_TAG=latest
ARG SNMP_DISCOVERY_TAG=latest
ARG GO_VERSION=1.24

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bullseye AS builder

RUN apt-get update && apt-get install --yes git make

WORKDIR /src/orb-agent

COPY . .

ARG TARGETOS TARGETARCH

RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /build/orb-agent ./cmd/main.go


FROM netboxlabs/opentelemetry-infinity:${OTEL_TAG} AS otlpinf

FROM netboxlabs/network-discovery:${NETWORK_DISCOVERY_TAG} AS network-discovery

FROM netboxlabs/snmp-discovery:${SNMP_DISCOVERY_TAG} AS snmp-discovery

FROM orbcommunity/pktvisor:${PKTVISOR_TAG} AS pktvisor

FROM python:3.12-slim-bullseye

RUN \
    apt update && \
    apt install --yes --no-install-recommends nmap openssh-client && \
    rm -rf /var/lib/apt

RUN mkdir -p /opt/orb

COPY --from=builder /build/orb-agent /usr/local/bin/orb-agent
COPY --from=builder /src/orb-agent/agent/docker/orb-agent-entry.sh /usr/local/bin/orb-agent-entry.sh
COPY --from=builder /src/orb-agent/agent/docker/run-agent.sh /run-agent.sh

COPY --from=pktvisor /usr/local/sbin/pktvisord /usr/local/bin/pktvisord
COPY --from=pktvisor /usr/local/sbin/crashpad_handler /usr/local/bin/crashpad_handler
COPY --from=pktvisor /geo-db /geo-db
COPY --from=pktvisor /iana /iana

COPY --from=otlpinf /exe /usr/local/bin/otlpinf

COPY --from=network-discovery /usr/local/bin/network-discovery /usr/local/bin/network-discovery
COPY --from=snmp-discovery /usr/local/bin/snmp-discovery /usr/local/bin/snmp-discovery

RUN pip3 install netboxlabs-device-discovery netboxlabs-orb-worker

RUN chmod a+x /run-agent.sh

ENTRYPOINT [ "/usr/local/bin/orb-agent-entry.sh" ]
