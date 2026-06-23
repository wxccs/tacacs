# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Daniel Wu.

GOCMD    := go
PACKAGES := ./...

.PHONY: all fmt vet build test cover lint tidy clean

all: build

## fmt: format all Go sources.
fmt:
	$(GOCMD) fmt $(PACKAGES)

## vet: run go vet on all packages.
vet:
	$(GOCMD) vet $(PACKAGES)

## build: compile all packages.
build:
	$(GOCMD) build $(PACKAGES)

## test: run all unit and integration tests.
test:
	$(GOCMD) test $(PACKAGES)

## cover: run tests with race detection and print coverage.
cover:
	$(GOCMD) test -race -coverprofile=coverage.out $(PACKAGES)
	$(GOCMD) tool cover -func=coverage.out

## lint: run golangci-lint (install separately if missing).
lint:
	golangci-lint run $(PACKAGES)

## tidy: tidy module dependencies.
tidy:
	$(GOCMD) mod tidy

## clean: remove generated artifacts.
clean:
	rm -f coverage.out
