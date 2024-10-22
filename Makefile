include agent/docker/.env

# expects to be set as env var
PRODUCTION_AGENT_REF_TAG ?= latest
PRODUCTION_AGENT_DEBUG_REF_TAG ?= latest-debug
REF_TAG ?= develop
DEBUG_REF_TAG ?= develop-debug
PKTVISOR_TAG ?= latest-develop
PKTVISOR_DEBUG_TAG ?= latest-develop-debug
DOCKER_IMAGE_NAME_PREFIX ?= orb
DOCKERHUB_REPO = netboxlabs
ORB_DOCKERHUB_REPO = netboxlabs
BUILD_DIR = build
CGO_ENABLED ?= 0
GOARCH ?= $(shell dpkg-architecture -q DEB_BUILD_ARCH)
GOOS ?= $(shell dpkg-architecture -q DEB_TARGET_ARCH_OS)
ORB_VERSION = $(shell cat VERSION)
COMMIT_HASH = $(shell git rev-parse --short HEAD)
OTEL_COLLECTOR_CONTRIB_VERSION ?= 0.91.0
OTEL_CONTRIB_URL ?= "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v$(OTEL_COLLECTOR_CONTRIB_VERSION)/otelcol-contrib_$(OTEL_COLLECTOR_CONTRIB_VERSION)_$(GOOS)_$(GOARCH).tar.gz"


define run_test
	 go test -mod=mod -short -race -count 1 -tags test $(shell go list ./... | grep -v 'cmd' | grep '$(SERVICE)')
endef

define run_test_coverage
	 go test -mod=mod -short -race -count 1 -tags test -cover -coverprofile=coverage.out -covermode=atomic $(shell go list ./... | grep -v 'cmd' | grep '$(SERVICE)')
endef

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
	docker volume ls -f name=$(DOCKER_IMAGE_NAME_PREFIX) -f dangling=true -q | xargs -r docker volume rm
endif

test:
	go test -mod=mod -short -race -count 1 -tags test $(shell go list ./... | grep -v 'cmd')

run_test_service: test_service $(2)

run_test_service_cov: test_service_cov $(2)

test_service:
	$(call run_test,$(@))

test_service_cov:
	$(call run_test_coverage,$(@))

agent_bin:
	echo "ORB_VERSION: $(ORB_VERSION)-$(COMMIT_HASH)"
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=$(GOARCH) GOARM=$(GOARM) go build -mod=mod -ldflags "-extldflags '-static' -X 'github.com/netboxlabs/orb-agent/buildinfo.version=$(ORB_VERSION)-$(COMMIT_HASH)'" -o ${BUILD_DIR}/$(DOCKER_IMAGE_NAME_PREFIX)-agent cmd/main.go

agent:
	docker build --no-cache \
	  --build-arg GOARCH=$(GOARCH) \
	  --build-arg PKTVISOR_TAG=$(PKTVISOR_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/$(DOCKER_IMAGE_NAME_PREFIX)-agent:$(REF_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/$(DOCKER_IMAGE_NAME_PREFIX)-agent:$(ORB_VERSION) \
	  --tag=$(ORB_DOCKERHUB_REPO)/$(DOCKER_IMAGE_NAME_PREFIX)-agent:$(ORB_VERSION)-$(COMMIT_HASH) \
	  -f agent/docker/Dockerfile .
	  
agent_full:
	docker build --no-cache \
	  --build-arg GOARCH=$(GOARCH) \
	  --build-arg PKTVISOR_TAG=$(PKTVISOR_TAG) \
	  --build-arg ORB_TAG=${REF_TAG} \
	  --build-arg OTEL_TAG=${OTEL_COLLECTOR_CONTRIB_VERSION} \
	  --tag=$(ORB_DOCKERHUB_REPO)/$(DOCKER_IMAGE_NAME_PREFIX)-agent-full:$(REF_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/$(DOCKER_IMAGE_NAME_PREFIX)-agent-full:$(ORB_VERSION) \
	  --tag=$(ORB_DOCKERHUB_REPO)/$(DOCKER_IMAGE_NAME_PREFIX)-agent-full:$(ORB_VERSION)-$(COMMIT_HASH) \
	  -f agent/docker/Dockerfile.full .

agent_debug:
	docker build \
	  --build-arg PKTVISOR_TAG=$(PKTVISOR_DEBUG_TAG) \
	  --tag=$(DOCKERHUB_REPO)/$(DOCKER_IMAGE_NAME_PREFIX)-agent:$(DEBUG_REF_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/$(DOCKER_IMAGE_NAME_PREFIX)-agent:$(DEBUG_REF_TAG) \
	  -f agent/docker/Dockerfile .

agent_production:
	docker build \
	  --build-arg PKTVISOR_TAG=$(PKTVISOR_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/$(DOCKER_IMAGE_NAME_PREFIX)-agent:$(PRODUCTION_AGENT_REF_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/$(DOCKER_IMAGE_NAME_PREFIX)-agent:$(ORB_VERSION) \
	  --tag=$(ORB_DOCKERHUB_REPO)/$(DOCKER_IMAGE_NAME_PREFIX)-agent:$(ORB_VERSION)-$(COMMIT_HASH) \
	  -f agent/docker/Dockerfile .

agent_debug_production:
	docker build \
	  --build-arg PKTVISOR_TAG=$(PKTVISOR_DEBUG_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/$(DOCKER_IMAGE_NAME_PREFIX)-agent:$(PRODUCTION_AGENT_DEBUG_REF_TAG) \
	  -f agent/docker/Dockerfile .

pull-latest-otel-collector-contrib:
	wget -O ./agent/backend/otel/otelcol_contrib.tar.gz $(OTEL_CONTRIB_URL)
	tar -xvf ./agent/backend/otel/otelcol_contrib.tar.gz -C ./agent/backend/otel/
	cp ./agent/backend/otel/otelcol-contrib .
	rm ./agent/backend/otel/otelcol_contrib.tar.gz
	rm ./agent/backend/otel/LICENSE
	rm ./agent/backend/otel/README.md
