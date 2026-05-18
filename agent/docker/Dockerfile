ARG PKTVISOR_TAG=develop-alpine
ARG OTEL_TAG=develop
ARG NETWORK_DISCOVERY_TAG=latest
ARG SNMP_DISCOVERY_TAG=latest
ARG GO_VERSION=1.26

########################################################################
# Builder stage stays on Debian because golang:${GO_VERSION}-trixie is the
# upstream-blessed toolchain image. The produced binary is CGO-disabled
# (see Makefile: CGO_ENABLED ?= 0) so it runs identically on any libc.
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
# pktvisor must be the Alpine/musl variant. The Debian/glibc image will
# fail to run on the Alpine final stage with "Exec format error".
FROM orbcommunity/pktvisor:${PKTVISOR_TAG} AS pktvisor

########################################################################
FROM python:3.14-alpine AS python-builder

# Build deps for native Python extensions that don't ship a musl wheel.
# In practice the heavy hitters (cffi, cryptography, grpcio, lxml,
# pydantic_core, PyNaCl) all publish musl wheels on PyPI, but we keep
# the toolchain here as a belt-and-braces guard against transient
# pip fallbacks-to-source. It is uninstalled before the final COPY.
RUN apk add --no-cache --virtual .build-deps \
        build-base \
        musl-dev \
        libffi-dev \
        openssl-dev \
        cargo \
        rust

# Upgrade pip to latest version with fewer vulnerabilities
RUN python -m pip install --upgrade --no-cache-dir pip==26.1 && \
    rm -rf /usr/local/lib/python3.14/ensurepip/_bundled/pip-*.whl

# Install Python packages
RUN pip3 install --no-cache-dir netboxlabs-device-discovery netboxlabs-orb-worker

RUN apk del .build-deps

########################################################################
FROM python:3.14-alpine

# Runtime tools:
#   bash           — orb-agent-entry.sh uses bash arrays (not POSIX sh)
#   ca-certificates — required for HTTPS verification (Doppler, fleet, Diode)
#   git            — used by the git config-manager strategy
#   gzip           — entry script decompresses /geo-db/*.mmdb.gz on first boot
#   nmap           — used by network-discovery for host probing
#   openssh-client — required by device-discovery (NAPALM/Netmiko SSH)
#   tini           — proper PID 1 / signal handling for the agent process
RUN apk add --no-cache \
        bash \
        ca-certificates \
        git \
        gzip \
        nmap \
        openssh-client \
        tini && \
    update-ca-certificates

RUN mkdir -p /opt/orb

# Copy Python site-packages and binaries from builder (includes pip and package executables)
COPY --from=python-builder /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages
COPY --from=python-builder /usr/local/bin /usr/local/bin

# Copy binaries from other stages
COPY --from=pktvisor /usr/local/sbin/pktvisord /usr/local/bin/pktvisord
COPY --from=pktvisor /usr/local/sbin/crashpad_handler /usr/local/bin/crashpad_handler
COPY --from=pktvisor /geo-db /geo-db
COPY --from=pktvisor /iana /iana

COPY --from=otlpinf /exe /usr/local/bin/otlpinf

COPY --from=network-discovery /usr/local/bin/network-discovery /usr/local/bin/network-discovery

COPY --from=snmp-discovery /usr/local/bin/snmp-discovery /usr/local/bin/snmp-discovery

COPY --from=builder /build/orb-agent /usr/local/bin/orb-agent
COPY --from=builder /src/orb-agent/agent/docker/orb-agent-entry.sh /usr/local/bin/orb-agent-entry.sh
COPY --from=builder /src/orb-agent/agent/docker/default_config.yaml /opt/orb/default_config.yaml

# tini lives at /sbin/tini on Alpine (it's /usr/bin/tini on Debian).
ENTRYPOINT [ "/sbin/tini", "--", "/usr/local/bin/orb-agent-entry.sh" ]
