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

RUN apk add --no-cache --virtual .build-deps \
        build-base \
        musl-dev \
        libffi-dev \
        openssl-dev \
        cargo \
        rust

RUN python -m pip install --upgrade --no-cache-dir pip==26.1 && \
    rm -rf /usr/local/lib/python3.14/ensurepip/_bundled/pip-*.whl

RUN pip3 install --no-cache-dir netboxlabs-device-discovery netboxlabs-orb-worker

RUN apk del .build-deps

########################################################################
FROM python:3.14-alpine

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

COPY --from=python-builder /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages
COPY --from=python-builder /usr/local/bin /usr/local/bin

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

ENTRYPOINT [ "/sbin/tini", "--", "/usr/local/bin/orb-agent-entry.sh" ]
