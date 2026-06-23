PRODUCTION_AGENT_REF_TAG ?= latest
PRODUCTION_AGENT_DEBUG_REF_TAG ?= latest-debug
REF_TAG ?= develop
DEBUG_REF_TAG ?= develop-debug
PKTVISOR_TAG ?= develop-alpine
PKTVISOR_DEBUG_TAG ?= develop-alpine-debug
SNMP_DISCOVERY_TAG ?= latest
DOCKERHUB_REPO = netboxlabs
ORB_DOCKERHUB_REPO = netboxlabs
BUILD_DIR ?= build
CGO_ENABLED ?= 0
GOARCH ?= $(shell go env GOARCH)
GOOS ?= $(shell go env GOOS)
ORB_VERSION ?= $(shell echo "$${BUILD_VERSION:-$$(cat agent/version/BUILD_VERSION.txt 2>/dev/null || git describe --tags --always 2>/dev/null || echo dev)}")
COMMIT_HASH = $(shell git rev-parse --short HEAD)
COMMIT_BRANCH = $(shell branch=$$(git rev-parse --abbrev-ref HEAD); if [ "$$branch" = "HEAD" ]; then branch=$${GITHUB_HEAD_REF:-$$GITHUB_REF_NAME}; fi; echo "$${branch:-unknown}")
VERSION_PKG = github.com/netboxlabs/orb-agent/agent/version
EXTRA_LDFLAGS ?=
LDFLAGS ?= -X $(VERSION_PKG).buildVersion=$(ORB_VERSION) -X $(VERSION_PKG).buildBranch=$(COMMIT_BRANCH) $(EXTRA_LDFLAGS)
OTEL_COLLECTOR_CONTRIB_VERSION ?= 0.91.0
OTEL_CONTRIB_URL ?= "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v$(OTEL_COLLECTOR_CONTRIB_VERSION)/otelcol-contrib_$(OTEL_COLLECTOR_CONTRIB_VERSION)_$(GOOS)_$(GOARCH).tar.gz"

.PHONY: agent agent_bin

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

.PHONY: install-dev-tools
install-dev-tools:
	@go install github.com/mfridman/tparse@latest

.PHONY: deps
deps:
	@go mod tidy

# Generate a local go.work spanning the agent and the Go discovery backends.
# Git-ignored — purely a local multi-module editing convenience; the agent
# image and CI build the agent as a single module.
.PHONY: work
work:
	@rm -f go.work go.work.sum
	@go work init . ./orb-discovery/network-discovery ./orb-discovery/snmp-discovery ./orb-discovery/gnmi-discovery
	@echo "go.work created (git-ignored). Use 'GOWORK=off' for single-module commands."

agent_bin:
	echo "ORB_VERSION: $(ORB_VERSION)-$(COMMIT_HASH)"
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) go build -mod=mod -ldflags="$(LDFLAGS)" -o ${BUILD_DIR}/orb-agent cmd/main.go

.PHONY: test
test:
	@go test -race ./...

.PHONY: test-timed
test-timed:
	@echo "Running tests with timing measurement..."
	@echo "=========================================="
	@start=$$(date +%s); \
	go test -count=1 ./...; \
	exit_code=$$?; \
	end=$$(date +%s); \
	duration=$$((end - start)); \
	echo "=========================================="; \
	echo "Test execution completed in $$duration seconds"; \
	exit $$exit_code

.PHONY: test-coverage
test-coverage:
	@mkdir -p .coverage
	@go test -race -cover -json -coverprofile=.coverage/cover.out.tmp ./... | grep -Ev "cmd|mocks" | tparse -format=markdown > .coverage/test-report.md
	@cat .coverage/cover.out.tmp | grep -Ev "cmd|mocks" > .coverage/cover.out
	@go tool cover -func=.coverage/cover.out | grep total | awk '{print substr($$3, 1, length($$3)-1)}' > .coverage/coverage.txt

.PHONY: lint
lint:
	@golangci-lint run ./... --config .github/golangci.yaml

.PHONY: fix-lint
fix-lint:
	@golangci-lint run ./... --config .github/golangci.yaml --fix

agent:
	docker build --no-cache \
	  --build-arg GOARCH=$(GOARCH) \
	  --build-arg PKTVISOR_TAG=$(PKTVISOR_TAG) \
	  --build-arg SNMP_DISCOVERY_TAG=$(SNMP_DISCOVERY_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(REF_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(ORB_VERSION) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(ORB_VERSION)-$(COMMIT_HASH) \
	  -f agent/docker/Dockerfile .

agent_fast:
	docker build \
	  --build-arg GOARCH=$(GOARCH) \
	  --build-arg PKTVISOR_TAG=$(PKTVISOR_TAG) \
	  --build-arg SNMP_DISCOVERY_TAG=$(SNMP_DISCOVERY_TAG) \
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