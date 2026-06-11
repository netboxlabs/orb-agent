ARG PKTVISOR_TAG=develop-alpine
ARG OTEL_TAG=develop
ARG NETWORK_DISCOVERY_TAG=latest
ARG SNMP_DISCOVERY_TAG=latest
ARG GO_VERSION=1.26

########################################################################
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-trixie AS builder

RUN apt-get update && apt-get install --yes git make

WORKDIR /src/orb-agent

COPY . .

ARG TARGETOS TARGETARCH

RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH EXTRA_LDFLAGS="-s -w" BUILD_DIR=/build make agent_bin

########################################################################
FROM netboxlabs/opentelemetry-infinity:${OTEL_TAG} AS otlpinf

########################################################################
FROM netboxlabs/network-discovery:${NETWORK_DISCOVERY_TAG} AS network-discovery

########################################################################
FROM netboxlabs/snmp-discovery:${SNMP_DISCOVERY_TAG} AS snmp-discovery

########################################################################
FROM netboxlabs/pktvisor:${PKTVISOR_TAG} AS pktvisor

########################################################################
FROM python:3.14-alpine AS python-builder

# Upgrade pip to latest version with fewer vulnerabilities
RUN python -m pip install --upgrade --no-cache-dir pip==26.1 && \
    rm -rf /usr/local/lib/python3.14/ensurepip/_bundled/pip-*.whl

# Install Python packages
RUN pip3 install --no-cache-dir netboxlabs-device-discovery netboxlabs-orb-worker

########################################################################
# Stage name is referenced by no-cache-filters in the build workflows so
# the apk upgrade layer below is never served from a stale build cache.
FROM python:3.14-alpine AS final

ENV TZ=UTC

# apk upgrade pulls the latest patched versions of base/transitive packages
# (e.g. libssh2, brought in by nmap) so image scans stay clean without
# per-package version pins.
RUN apk upgrade --no-cache && \
    apk add --no-cache \
        bash \
        ca-certificates \
        git \
        gzip \
        nmap \
        openssh-client \
        tini \
        tzdata && \
    cp /usr/share/zoneinfo/UTC /etc/localtime && \
    echo "UTC" > /etc/timezone && \
    update-ca-certificates

RUN mkdir -p /opt/orb /opt/orb/files /opt/orb/pip-cache /usr/local/share/orb-agent

ENV PATH=/opt/orb/files:$PATH
ENV PIP_CACHE_DIR=/opt/orb/pip-cache
ENV ORB_DEFAULT_CONFIG=/usr/local/share/orb-agent/default_config.yaml

# Copy Python site-packages and binaries from builder (includes pip and package executables)
COPY --from=python-builder /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages
COPY --from=python-builder /usr/local/bin /usr/local/bin

# Copy binaries from other stages
COPY --from=pktvisor /usr/local/sbin/pktvisord /usr/local/bin/pktvisord
COPY --from=pktvisor /geo-db /geo-db
COPY --from=pktvisor /iana /iana

COPY --from=otlpinf /exe /usr/local/bin/otlpinf

COPY --from=network-discovery /usr/local/bin/network-discovery /usr/local/bin/network-discovery

COPY --from=snmp-discovery /usr/local/bin/snmp-discovery /usr/local/bin/snmp-discovery

COPY --from=builder /build/orb-agent /usr/local/bin/orb-agent
COPY --from=builder /src/orb-agent/agent/docker/orb-agent-entry.sh /usr/local/bin/orb-agent-entry.sh
COPY --from=builder /src/orb-agent/agent/docker/default_config.yaml /usr/local/share/orb-agent/default_config.yaml

ENTRYPOINT [ "/sbin/tini", "--", "/usr/local/bin/orb-agent-entry.sh" ]
