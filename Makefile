# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2026 Daniel Wu.
#
# This library is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# This library is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library. If not, see <https://www.gnu.org/licenses/>.

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
