PRODUCTION_AGENT_REF_TAG ?= latest
PRODUCTION_AGENT_DEBUG_REF_TAG ?= latest-debug
REF_TAG ?= develop
DEBUG_REF_TAG ?= develop-debug
PKTVISOR_TAG ?= develop-alpine
PKTVISOR_DEBUG_TAG ?= develop-alpine-debug
DOCKERHUB_REPO = netboxlabs
ORB_DOCKERHUB_REPO = netboxlabs
BUILD_DIR ?= build
CGO_ENABLED ?= 0
GOARCH ?= $(shell go env GOARCH)
GOOS ?= $(shell go env GOOS)
# CI sets BUILD_VERSION (release) or writes agent/version/BUILD_VERSION.txt
# (develop/PR). A bare local build has neither, so it is stamped local-<sha> to
# make clear it was built locally — distinct from a develop or release image.
ORB_VERSION ?= $(shell echo "$${BUILD_VERSION:-$$(cat agent/version/BUILD_VERSION.txt 2>/dev/null || echo local-$$(git rev-parse --short HEAD 2>/dev/null || echo unknown))}")
COMMIT_HASH = $(shell git rev-parse --short HEAD)
COMMIT_BRANCH = $(shell branch=$$(git rev-parse --abbrev-ref HEAD); if [ "$$branch" = "HEAD" ]; then branch=$${GITHUB_HEAD_REF:-$$GITHUB_REF_NAME}; fi; echo "$${branch:-unknown}")
VERSION_PKG = github.com/netboxlabs/orb-agent/agent/version
EXTRA_LDFLAGS ?=
LDFLAGS ?= -X $(VERSION_PKG).buildVersion=$(ORB_VERSION) -X $(VERSION_PKG).buildBranch=$(COMMIT_BRANCH) $(EXTRA_LDFLAGS)
# Backend versions stamped into the from-source image (latest <backend>/v* tag);
# without these the from-source backends report 0.0.0. List the tags rather than
# `git describe` so the result does not depend on the tag being reachable from
# HEAD (backend tags are cut on the `release` branch), matching how the CI
# workflows resolve versions. The grep keeps only released X.Y.Z tags, so the
# dot-field numeric sort below is equivalent to `sort -V` but portable to the
# BSD `sort` on contributor macOS machines (which lacks GNU's -V).
ND_VERSION ?= $(shell v=$$(git tag -l 'network-discovery/v[0-9]*' | sed 's|.*/v||' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$$' | sort -t. -k1,1n -k2,2n -k3,3n | tail -1); echo $${v:-0.0.0})
SD_VERSION ?= $(shell v=$$(git tag -l 'snmp-discovery/v[0-9]*' | sed 's|.*/v||' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$$' | sort -t. -k1,1n -k2,2n -k3,3n | tail -1); echo $${v:-0.0.0})
DD_VERSION ?= $(shell v=$$(git tag -l 'device-discovery/v[0-9]*' | sed 's|.*/v||' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$$' | sort -t. -k1,1n -k2,2n -k3,3n | tail -1); echo $${v:-0.0.0})
WK_VERSION ?= $(shell v=$$(git tag -l 'worker/v[0-9]*' | sed 's|.*/v||' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$$' | sort -t. -k1,1n -k2,2n -k3,3n | tail -1); echo $${v:-0.0.0})
GD_VERSION ?= $(shell v=$$(git tag -l 'gnmi-discovery/v[0-9]*' | sed 's|.*/v||' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$$' | sort -t. -k1,1n -k2,2n -k3,3n | tail -1); echo $${v:-0.0.0})
ST_VERSION ?= $(shell v=$$(git tag -l 'snmp-telemetry/v[0-9]*' | sed 's|.*/v||' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$$' | sort -t. -k1,1n -k2,2n -k3,3n | tail -1); echo $${v:-0.0.0})
BACKEND_VERSION_ARGS = --build-arg NETWORK_DISCOVERY_VERSION=$(ND_VERSION) --build-arg SNMP_DISCOVERY_VERSION=$(SD_VERSION) --build-arg GNMI_DISCOVERY_VERSION=$(GD_VERSION) --build-arg SNMP_TELEMETRY_VERSION=$(ST_VERSION) --build-arg DEVICE_DISCOVERY_VERSION=$(DD_VERSION) --build-arg WORKER_VERSION=$(WK_VERSION) --build-arg BUILD_COMMIT=$(COMMIT_HASH) --build-arg BUILD_TRACK=$(COMMIT_BRANCH)

# Make targets operate on the agent (a single module), so never use a local
# go.work — workspace mode is incompatible with the -mod=mod build flow. The
# `work` target below re-enables it explicitly for generating the file.
export GOWORK = off

# Backends, grouped by toolchain — used by the *-all aggregate targets. Go
# backends carry their parent directory since they are not all under
# orb-discovery/ (snmp-telemetry lives under orb-telemetry/).
GO_BACKENDS = orb-discovery/network-discovery orb-discovery/snmp-discovery orb-discovery/gnmi-discovery orb-telemetry/snmp-telemetry orb-telemetry/gnmi-telemetry
PY_BACKENDS = device-discovery worker

.PHONY: agent agent_bin

clean:
	rm -rf ${BUILD_DIR}

.PHONY: install-dev-tools
# Tool versions are pinned to match CI (.github/workflows) so local
# lint-all/test-all reproduce the blocking CI jobs: golangci-lint v2.11.4 +
# ruff 0.15.10 (lint.yaml), tparse v0.14.0 (tests.yaml) + gcov2lcov v1.1.1
# (_backend-test-go.yaml). Keep these in sync when CI bumps them.
install-dev-tools:
	@go install github.com/mfridman/tparse@v0.14.0
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4
	@go install github.com/jandelgado/gcov2lcov@v1.1.1
	@for b in $(PY_BACKENDS); do \
		echo ">> orb-discovery/$$b: venv + dev/test deps"; \
		( cd orb-discovery/$$b && \
		  { test -d .venv || python3 -m venv .venv; } && \
		  . .venv/bin/activate && \
		  pip install -q -e '.[dev,test]' && \
		  pip install -q ruff==0.15.10 ) || exit 1; \
	done

.PHONY: deps
deps:
	@go mod tidy

# Generate a local go.work spanning the agent and the Go discovery backends.
# Git-ignored — purely a local multi-module editing convenience; the agent
# image and CI build the agent as a single module.
.PHONY: work
work:
	@rm -f go.work go.work.sum
	@GOWORK= go work init . ./orb-discovery/network-discovery ./orb-discovery/snmp-discovery ./orb-discovery/gnmi-discovery ./orb-telemetry/snmp-telemetry
	@echo "go.work created (git-ignored). Use 'GOWORK=off' for single-module commands."

agent_bin:
	echo "ORB_VERSION: $(ORB_VERSION)"
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
	@go tool cover -func=.coverage/cover.out | grep -E '^total:' | awk '{print substr($$3, 1, length($$3)-1)}' > .coverage/coverage.txt

.PHONY: lint
lint:
	@golangci-lint run ./... --config .github/golangci.yaml

.PHONY: fix-lint
fix-lint:
	@golangci-lint run ./... --config .github/golangci.yaml --fix

.PHONY: lint-all
lint-all: lint
	@for b in $(GO_BACKENDS); do $(MAKE) -C $$b lint || exit 1; done
	@for b in $(PY_BACKENDS); do \
		test -d orb-discovery/$$b/.venv || { echo "missing orb-discovery/$$b/.venv — run 'make install-dev-tools'"; exit 1; }; \
		( cd orb-discovery/$$b && . .venv/bin/activate && ruff check . ) || exit 1; \
	done

.PHONY: fix-lint-all
fix-lint-all: fix-lint
	@for b in $(GO_BACKENDS); do $(MAKE) -C $$b fix-lint || exit 1; done
	@for b in $(PY_BACKENDS); do \
		test -d orb-discovery/$$b/.venv || { echo "missing orb-discovery/$$b/.venv — run 'make install-dev-tools'"; exit 1; }; \
		( cd orb-discovery/$$b && . .venv/bin/activate && ruff check --fix . ) || exit 1; \
	done

.PHONY: test-all
test-all: test
	@for b in $(GO_BACKENDS); do $(MAKE) -C $$b test || exit 1; done
	@for b in $(PY_BACKENDS); do \
		test -d orb-discovery/$$b/.venv || { echo "missing orb-discovery/$$b/.venv — run 'make install-dev-tools'"; exit 1; }; \
		( cd orb-discovery/$$b && . .venv/bin/activate && pytest ) || exit 1; \
	done

agent:
	docker build --no-cache \
	  --build-arg GOARCH=$(GOARCH) \
	  --build-arg PKTVISOR_TAG=$(PKTVISOR_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(REF_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(ORB_VERSION) \
	  $(BACKEND_VERSION_ARGS) \
	  -f agent/docker/Dockerfile .

agent_fast:
	docker build \
	  --build-arg GOARCH=$(GOARCH) \
	  --build-arg PKTVISOR_TAG=$(PKTVISOR_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(REF_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(ORB_VERSION) \
	  $(BACKEND_VERSION_ARGS) \
	  -f agent/docker/Dockerfile .

agent_debug:
	docker build \
	  --build-arg PKTVISOR_TAG=$(PKTVISOR_DEBUG_TAG) \
	  --tag=$(DOCKERHUB_REPO)/orb-agent:$(DEBUG_REF_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(DEBUG_REF_TAG) \
	  $(BACKEND_VERSION_ARGS) \
	  -f agent/docker/Dockerfile .

agent_production:
	docker build \
	  --build-arg PKTVISOR_TAG=$(PKTVISOR_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(PRODUCTION_AGENT_REF_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(ORB_VERSION) \
	  $(BACKEND_VERSION_ARGS) \
	  -f agent/docker/Dockerfile .

agent_debug_production:
	docker build \
	  --build-arg PKTVISOR_TAG=$(PKTVISOR_DEBUG_TAG) \
	  --tag=$(ORB_DOCKERHUB_REPO)/orb-agent:$(PRODUCTION_AGENT_DEBUG_REF_TAG) \
	  $(BACKEND_VERSION_ARGS) \
	  -f agent/docker/Dockerfile .