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

.PHONY: clean
clean:
	@rm -rf ${BUILD_DIR}/*

.PHONY: build
build:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) go build -mod=mod -o ${BUILD_DIR}/gnmi-discovery cmd/main.go

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
