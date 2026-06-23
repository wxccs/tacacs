# tacacs

[![Go Reference](https://pkg.go.dev/badge/github.com/wxccs/tacacs.svg)](https://pkg.go.dev/github.com/wxccs/tacacs)
[![License: LGPL-3.0-or-later](https://img.shields.io/badge/License-LGPL--3.0--or--later-blue.svg)](./LICENSE)

A commercial-grade Go implementation of the TACACS+ protocol suite.

`tacacs` is a pure-Go library that implements the full family of TACACS
specifications published by the IETF, together with a `tacacs-cli` command-line
tool for interoperability testing:

| RFC | Title | Role |
|-----|-------|------|
| [RFC 1492](https://www.rfc-editor.org/rfc/rfc1492) | An Access Control Protocol, Sometimes Called TACACS | original TACACS (legacy) |
| [RFC 8907](https://www.rfc-editor.org/rfc/rfc8907) | The TACACS+ Protocol | base protocol |
| [RFC 9887](https://www.rfc-editor.org/rfc/rfc9887) | TACACS+ over TLS 1.3 | secure transport |
| [RFC 9950](https://www.rfc-editor.org/rfc/rfc9950) | A YANG Data Model for TACACS+ | configuration model |

## Features

- Authentication (ASCII, PAP, CHAP, MS-CHAP, MS-CHAPv2), authorization and
  accounting (start / stop / watchdog) per RFC 8907.
- MD5-based body obfuscation (RFC 8907 §4.5) and TLS 1.3 transport (RFC 9887),
  which obsoletes obfuscation over TLS.
- A YANG-aligned configuration model (RFC 9950) loadable from YAML and JSON.
- The original TACACS protocol (RFC 1492) in both its TCP (ASCII) and UDP
  (simple / extended) encodings.
- A dependency-free core with an injectable logger; `tacacs-cli` uses
  [cobra](https://github.com/spf13/cobra) and
  [viper](https://github.com/spf13/viper).

> **Status:** work in progress. The library is built in phases; see the project
> plan. This README is expanded as the higher-level APIs land.

## Installation

```bash
go get github.com/wxccs/tacacs
```

Requires Go 1.26 or later.

## Quick start

The high-level `client` and `server` packages are added in later phases. Once
available:

```go
import "github.com/wxccs/tacacs/client"
```

For now, the `packet`, `crypto`, `types` and `errors` packages are usable
directly for low-level TACACS+ packet construction and inspection.

## Project layout

```
.
├── errors/          typed sentinel errors
├── types/           protocol constants, Logger interface, argument codec
├── packet/          header and body marshalling (RFC 8907)
├── crypto/           MD5 pseudo-pad obfuscation (RFC 8907 §4.5)
├── protocol/        authentication/authorization/accounting state machines
├── transport/       TCP and TLS 1.3 transports (RFC 9887)
├── yang/            RFC 9950 configuration model
├── client/          high-level client API
├── server/          server-side handlers
├── legacy/          RFC 1492 original TACACS
├── cmd/tacacs-cli/  command-line tool
└── docs/rfc/        source RFC texts
```

## Development

```bash
make tidy        # go mod tidy
make fmt         # gofmt
make vet         # go vet
make test        # unit + integration tests
make cover       # coverage report (target >= 90%)
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the code and logging conventions.

## License

Copyright (C) 2026 The tacacs authors.

This library is free software: you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version. See [LICENSE](./LICENSE) for the full text.
