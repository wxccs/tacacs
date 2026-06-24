# tacacs

[![Go Reference](https://pkg.go.dev/badge/github.com/wxccs/tacacs.svg)](https://pkg.go.dev/github.com/wxccs/tacacs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

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
- A dependency-free core with an injectable `log/slog`-compatible logger;
  `tacacs-cli` uses [cobra](https://github.com/spf13/cobra),
  [viper](https://github.com/spf13/viper) and
  [logrus](https://github.com/sirupsen/logrus).

> **Status:** work in progress. The library is built in phases; see the project
> plan. This README is expanded as the higher-level APIs land.

## Installation

```bash
go get github.com/wxccs/tacacs
```

Requires Go 1.26 or later.

## Quick start

### Client

```go
import (
    "context"
    "github.com/wxccs/tacacs/client"
    "github.com/wxccs/tacacs/transport"
    "github.com/wxccs/tacacs/types"
)

func authenticate() error {
    conn, err := transport.Dial(context.Background(), "tcp", "tacacs.example.com:49",
        []byte("sharedsecret"))
    if err != nil {
        return err
    }
    defer conn.Close()

    c, err := client.New(conn)
    if err != nil {
        return err
    }
    reply, err := c.Authenticate(context.Background(), client.AuthenRequest{
        Action: types.AuthenLogin, Type: types.AuthenTypePAP, Service: types.AuthenServiceLogin,
        User: "alice", Data: []byte("password"),
    }, nil)
    if err != nil {
        return err
    }
    // reply.Status == types.AuthenStatusPass on success.
    return nil
}
```

For TLS 1.3 (RFC 9887), use `transport.DialTLS` with a `transport.TLSConfig`
instead of `transport.Dial`.

### Server

Implement the `server.Handler` interface and serve connections:

```go
import (
    "context"
    "github.com/wxccs/tacacs/server"
    "github.com/wxccs/tacacs/transport"
    "github.com/wxccs/tacacs/types"
)

type myHandler struct{}

func (myHandler) Authenticate(ctx context.Context, ac server.AuthenContext, cont *server.AuthenContinue) (server.AuthenDecision, error) {
    // ...verify credentials...
    return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
}
func (myHandler) Authorize(ctx context.Context, ac server.AuthorContext) (server.AuthorDecision, error) {
    return server.AuthenDecision{Status: types.AuthorStatusPassAdd}, nil
}
func (myHandler) Account(ctx context.Context, ac server.AcctContext) (server.AcctDecision, error) {
    return server.AcctDecision{Status: types.AcctStatusSuccess}, nil
}

// ln is a net.Listener (use transport.ListenTLS for TLS 1.3).
srv := server.New(server.Config{Handler: myHandler{}, Secret: []byte("sharedsecret"), Mode: transport.ModeLegacy})
for {
    c, _ := ln.Accept()
    conn := transport.Accept(c, transport.ModeLegacy, []byte("sharedsecret"))
    go srv.ServeConn(context.Background(), conn)
}
```

### Configuration (RFC 9950)

Load a server list from YAML or JSON:

```go
import "github.com/wxccs/tacacs/yang"

cfg, err := yang.Load("tacacs.yaml")
// cfg.Servers is the unified, ordered server list.
```

See [`docs/examples/`](./docs/examples) for shared-secret and TLS example
configurations matching the RFC 9950 appendices.

### Command-line tool

```bash
# Run the test server
tacacs-cli server --listen 127.0.0.1 --port 49 --secret testkey

# Authenticate (client)
tacacs-cli auth --server 127.0.0.1 --port 49 --secret testkey \
    --username admin --password admin123 --type pap --output json

# Authorize a command
tacacs-cli authz --server 127.0.0.1 --port 49 --secret testkey \
    --username admin --service shell --cmd "show version"

# Accounting
tacacs-cli acct --server 127.0.0.1 --port 49 --secret testkey \
    --username admin --action start
```

For low-level packet construction and inspection, the `packet`, `crypto`,
`types` and `errors` packages are usable directly.

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

Copyright (c) 2026 Daniel Wu

This library is licensed under the MIT License. See [LICENSE](./LICENSE) for
the full text.

Third-party dependencies and their license terms are documented in
[THIRD_PARTY_LICENSES.md](./THIRD_PARTY_LICENSES.md).
