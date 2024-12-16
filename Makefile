include agent/docker/.env

# expects to be set as env var
PRODUCTION_AGENT_REF_TAG ?= latest
PRODUCTION_AGENT_DEBUG_REF_TAG ?= latest-debug
REF_TAG ?= develop
DEBUG_REF_TAG ?= develop-debug
PKTVISOR_TAG ?= develop
PKTVISOR_DEBUG_TAG ?= develop-debug
DOCKERHUB_REPO = netboxlabs
ORB_DOCKERHUB_REPO = netboxlabs
BUILD_DIR = build
CGO_ENABLED ?= 0
GOARCH ?= $(shell go env GOARCH)
GOOS ?= $(shell go env GOOS)
ORB_VERSION = $(shell cat agent/version/BUILD_VERSION.txt)
COMMIT_HASH = $(shell git rev-parse --short HEAD)
OTEL_COLLECTOR_CONTRIB_VERSION ?= 0.91.0
OTEL_CONTRIB_URL ?= "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v$(OTEL_COLLECTOR_CONTRIB_VERSION)/otelcol-contrib_$(OTEL_COLLECTOR_CONTRIB_VERSION)_$(GOOS)_$(GOARCH).tar.gz"

all: platform

.PHONY: all agent agent_bin

clean:
	rm -rf ${BUILD_DIR}

cleandocker:
	# Stops containers and removes containers, networks, volumes, and images created by up
#	docker-compose -f docker/docker-compose.yml down --rmi all -v --remove-orphans
	docker-compose -f docker/docker-compose.yml down -v --remove-orphans

ifdef pv
	# Remove unused volumes
	docker volume ls -f name=orb -f dangling=true -q | xargs -r docker volume rm
endif


agent_bin:
	echo "ORB_VERSION: $(ORB_VERSION)-$(COMMIT_HASH)"
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=$(GOARCH) GOARM=$(GOARM) go build -mod=mod -o ${BUILD_DIR}/orb-agent cmd/main.go

.PHONY: test-coverage
test-coverage:
	@mkdir -p .coverage
	@go test -race -cover -json -coverprofile=.coverage/cover.out.tmp ./... | grep -Ev "cmd" | tparse -format=markdown > .coverage/test-report.md
	@cat .coverage/cover.out.tmp | grep -Ev "cmd" > .coverage/cover.out
	@go tool cover -func=.coverage/cover.out | grep total | awk '{print substr($$3, 1, length($$3)-1)}' > .coverage/coverage.txt

agent:
	docker build --no-cache \
	  --build-arg GOARCH=$(GOARCH) \
	  --build-arg PKTVISOR_TAG=$(PKTVISOR_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(REF_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(ORB_VERSION) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(ORB_VERSION)-$(COMMIT_HASH) \
	  -f agent/docker/Dockerfile .

agent_debug:
	docker build \
	  --build-arg PKTVISOR_TAG=$(PKTVISOR_DEBUG_TAG) \
	  --tag=$(DOCKERHUB_REPO)/orb-agent:$(DEBUG_REF_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(DEBUG_REF_TAG) \
	  -f agent/docker/Dockerfile .

agent_production:
	docker build \
	  --build-arg PKTVISOR_TAG=$(PKTVISOR_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(PRODUCTION_AGENT_REF_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(ORB_VERSION) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(ORB_VERSION)-$(COMMIT_HASH) \
	  -f agent/docker/Dockerfile .

agent_debug_production:
	docker build \
	  --build-arg PKTVISOR_TAG=$(PKTVISOR_DEBUG_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(PRODUCTION_AGENT_DEBUG_REF_TAG) \
	  -f agent/docker/Dockerfile .

pull-latest-otel-collector-contrib:
	wget -O ./agent/backend/otel/otelcol_contrib.tar.gz $(OTEL_CONTRIB_URL)
	tar -xvf ./agent/backend/otel/otelcol_contrib.tar.gz -C ./agent/backend/otel/
	cp ./agent/backend/otel/otelcol-contrib .
	rm ./agent/backend/otel/otelcol_contrib.tar.gz
	rm ./agent/backend/otel/LICENSE
	rm ./agent/backend/otel/README.md
