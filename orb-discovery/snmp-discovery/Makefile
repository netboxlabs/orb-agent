# Every target runs outside the repository workspace, which is what CI does and
# what keeps this module buildable on its own. Without it a generated go.work
# puts the build in workspace mode, where -mod=mod is rejected.
export GOWORK = off

CGO_ENABLED ?= 0
BUILD_DIR ?= ./build
GOARCH ?= $(shell go env GOARCH)
GOOS ?= $(shell go env GOOS)
VERSION_DIR ?= ./version
VERSION := $(shell cat $(VERSION_DIR)/BUILD_VERSION.txt)
COMMIT_SHA := $(shell git rev-parse --short HEAD)

.PHONY: install-dev-tools
install-dev-tools:
	@go install github.com/mfridman/tparse@latest
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	@go install github.com/jandelgado/gcov2lcov@latest
	
.PHONY: build
clean:
	@rm -rf ${BUILD_DIR}/*

.PHONY: build
build:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) go build -mod=mod -o ${BUILD_DIR}/snmp-discovery cmd/main.go

.PHONY: deps
deps:
	@go mod tidy

.PHONY: lint
lint:
	@golangci-lint run ./... --config ../../.github/golangci.yaml

.PHONY: fix-lint
fix-lint:
	@golangci-lint run ./... --config ../../.github/golangci.yaml --fix

# go test writes its events to a file so its exit status is kept: piping it
# straight into the cmd filter let a failing cmd test leave the build green,
# because the filter dropped the failure event and reported its own status.
# Both filters are anchored to the package so a test name or a line of output
# containing "cmd" is not dropped with it.
.PHONY: test-coverage
test-coverage:
	@mkdir -p .coverage
	@go test -race -cover -json -coverprofile=.coverage/cover.out.tmp ./... > .coverage/test-events.json; \
		status=$$?; \
		grep -Ev '"Package":"[^"]*/cmd"' .coverage/test-events.json | tparse -format=markdown > .coverage/test-report.md || status=$$?; \
		exit $$status
	@grep -Ev '/cmd/' .coverage/cover.out.tmp > .coverage/cover.out
	@go tool cover -func=.coverage/cover.out | grep -E '^total:' | awk '{print substr($$3, 1, length($$3)-1)}' > .coverage/coverage.txt
	@gcov2lcov -infile=.coverage/cover.out -outfile=.coverage/lcov.info

.PHONY: test
test:
	@go test -race ./...

# Integration tests against orb-test-lab SNMP simulators (172.28.0.20–22, .24).
# Requires: `make up` in eng-observability-skunkworks/orb-test-lab.
# Runs inside Docker on the orb-test-lab network so simulators are reachable.
INTEGRATION_GO_IMAGE ?= golang:1.26.4
.PHONY: test-integration test-integration-local
test-integration:
	@if ! docker network inspect orb-test-lab >/dev/null 2>&1; then \
		echo "orb-test-lab network not found; start the lab: cd ../../../eng-observability-skunkworks/orb-test-lab && make up"; \
		exit 1; \
	fi
	docker run --rm --network orb-test-lab \
		-v "$(CURDIR):/work" -w /work \
		-e CGO_ENABLED=0 \
		$(INTEGRATION_GO_IMAGE) \
		go test -tags=integration -timeout=8m -count=1 -v ./e2e/...

test-integration-local:
	go test -tags=integration -timeout=8m -count=1 -v ./e2e/...