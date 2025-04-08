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
	@golangci-lint run ./... --config ../.github/golangci.yaml

.PHONY: fix-lint
fix-lint:
	@golangci-lint run ./... --config ../.github/golangci.yaml --fix

.PHONY: test-coverage
test-coverage:
	@mkdir -p .coverage
	@go test -race -cover -json -coverprofile=.coverage/cover.out.tmp ./... | grep -Ev "cmd" | tparse -format=markdown > .coverage/test-report.md
	@cat .coverage/cover.out.tmp | grep -Ev "cmd" > .coverage/cover.out
	@go tool cover -func=.coverage/cover.out | grep total | awk '{print substr($$3, 1, length($$3)-1)}' > .coverage/coverage.txt


.PHONY: test
test:
	@go test -race ./...