# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Daniel Wu.

GOCMD    := go
PACKAGES := ./...
# FUZZTIME bounds each fuzz target in `make fuzz`; override for longer local runs.
FUZZTIME ?= 20s
# FUZZPKGS lists packages whose decoders parse untrusted input.
FUZZPKGS := ./crypto ./legacy ./packet ./transport ./transport/proxy ./types

.PHONY: all fmt vet build test cover lint tidy clean fuzz

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

## fuzz: run every Fuzz* target briefly to catch parser crashes (FUZZTIME=20s).
fuzz:
	@for pkg in $(FUZZPKGS); do \
		for fn in $$($(GOCMD) test -list '^Fuzz' $$pkg | grep '^Fuzz'); do \
			echo ">>> $$pkg $$fn"; \
			$(GOCMD) test $$pkg -run '^$$' -fuzz "^$$fn$$" -fuzztime=$(FUZZTIME) || exit 1; \
		done; \
	done

## clean: remove generated artifacts.
clean:
	rm -f coverage.out
