ARG PKTVISOR_TAG=develop-alpine
ARG OTEL_TAG=develop
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
# network-discovery is built from in-repo source (orb-discovery/network-discovery)
# rather than a published image, so the binary tracks the current Go stdlib and
# pinned deps — no :latest staleness in scans. Reuses the backend's own build
# pattern (CGO_ENABLED=0, -trimpath, -ldflags="-s -w").
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-trixie AS network-discovery

WORKDIR /src/network-discovery

COPY orb-discovery/network-discovery/ .

ARG TARGETOS TARGETARCH
# Stamp the backend version: its version package go:embeds version/BUILD_*.txt.
ARG NETWORK_DISCOVERY_VERSION=0.0.0
ARG BUILD_COMMIT=unknown

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    echo "${NETWORK_DISCOVERY_VERSION}" > version/BUILD_VERSION.txt && \
    echo "${BUILD_COMMIT}" > version/BUILD_COMMIT.txt && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -ldflags="-s -w" -trimpath -o /usr/local/bin/network-discovery ./cmd/main.go

########################################################################
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-trixie AS snmp-discovery

WORKDIR /src/snmp-discovery

COPY orb-discovery/snmp-discovery/ .

ARG TARGETOS TARGETARCH
# Stamp the backend version: its version package go:embeds version/BUILD_*.txt.
ARG SNMP_DISCOVERY_VERSION=0.0.0
ARG BUILD_COMMIT=unknown

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    echo "${SNMP_DISCOVERY_VERSION}" > version/BUILD_VERSION.txt && \
    echo "${BUILD_COMMIT}" > version/BUILD_COMMIT.txt && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -ldflags="-s -w" -trimpath -o /usr/local/bin/snmp-discovery ./cmd/main.go

########################################################################
FROM netboxlabs/pktvisor:${PKTVISOR_TAG} AS pktvisor

########################################################################
FROM python:3.14-alpine AS python-builder

# Upgrade pip to latest version with fewer vulnerabilities
RUN python -m pip install --upgrade --no-cache-dir pip==26.1 && \
    rm -rf /usr/local/lib/python3.14/ensurepip/_bundled/pip-*.whl

# Install the Python backends from in-repo source (was: published PyPI packages
# netboxlabs-device-discovery / netboxlabs-orb-worker). Console scripts
# device-discovery and orb-worker land in /usr/local/bin.
# Stamp backend versions into version.py (the release pipeline does this via sed;
# mirror it so the from-source build reports real versions, not 0.0.0).
ARG DEVICE_DISCOVERY_VERSION=0.0.0
ARG WORKER_VERSION=0.0.0
ARG BUILD_COMMIT=unknown
ARG BUILD_TRACK=dev

COPY orb-discovery/device-discovery/ /src/device-discovery/
COPY orb-discovery/worker/ /src/worker/
COPY agent/docker/stamp_version.py /tmp/stamp_version.py
RUN BUILD_COMMIT="${BUILD_COMMIT}" BUILD_TRACK="${BUILD_TRACK}" \
      python /tmp/stamp_version.py "${DEVICE_DISCOVERY_VERSION}" /src/device-discovery/device_discovery/version.py && \
    BUILD_COMMIT="${BUILD_COMMIT}" BUILD_TRACK="${BUILD_TRACK}" \
      python /tmp/stamp_version.py "${WORKER_VERSION}" /src/worker/worker/version.py
RUN pip3 install --no-cache-dir /src/device-discovery /src/worker

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
