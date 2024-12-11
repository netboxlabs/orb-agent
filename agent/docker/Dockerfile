ARG PKTVISOR_TAG=latest-develop
ARG OTEL_TAG=0.111.0
ARG NETWORK_DISCOVERY_TAG=latest
ARG GO_VERSION=1.23

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bullseye AS builder

RUN apt-get update && apt-get install --yes git make

WORKDIR /src/orb-agent

COPY . .

ARG TARGETOS TARGETARCH

RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=1 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /build/orb-agent ./cmd/main.go


FROM otel/opentelemetry-collector-contrib:${OTEL_TAG} AS otelcol-contrib

FROM netboxlabs/network-discovery:${NETWORK_DISCOVERY_TAG} AS network-discovery

FROM orbcommunity/pktvisor:${PKTVISOR_TAG} AS pktvisor

FROM python:3.12-slim-bullseye

RUN \
    apt update && \
    apt install --yes --force-yes --no-install-recommends nmap && \
    rm -rf /var/lib/apt

RUN addgroup --system netdev && useradd -m --shell /bin/bash -G netdev appuser && echo "appuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Create necessary directories and set ownership to appuser
RUN mkdir -p /opt/orb && chown appuser:appuser /opt/orb \
    && chown appuser:appuser /usr/local/bin \
    && chown appuser:appuser /var/run

COPY --from=builder /build/orb-agent /usr/local/bin/orb-agent
COPY --from=builder /src/orb-agent/agent/docker/agent_default.yaml /opt/orb/agent_default.yaml
COPY --from=builder /src/orb-agent/agent/docker/orb-agent-entry.sh /usr/local/bin/orb-agent-entry.sh
COPY --from=builder /src/orb-agent/agent/docker/run-agent.sh /run-agent.sh

COPY --from=pktvisor /usr/local/sbin/pktvisord /usr/local/sbin/pktvisord
COPY --from=pktvisor /usr/local/sbin/crashpad_handler /usr/local/sbin/crashpad_handler
COPY --from=pktvisor /geo-db /geo-db
COPY --from=pktvisor /iana /iana

RUN  chown appuser:appuser /geo-db

COPY --from=otelcol-contrib /otelcol-contrib /usr/local/bin/otelcol-contrib

COPY --from=network-discovery /usr/local/bin/network-discovery /usr/local/bin/network-discovery

RUN pip3 install netboxlabs-device-discovery

RUN chmod a+x /run-agent.sh

USER appuser

ENTRYPOINT [ "/usr/local/bin/orb-agent-entry.sh" ]
