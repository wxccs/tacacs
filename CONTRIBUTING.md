# Contributing to tacacs

Thank you for your interest in contributing to the `tacacs` project.

## Development setup

```bash
git clone https://github.com/wxccs/tacacs.git
cd tacacs
go mod tidy
go test ./...
```

Requires Go 1.26 or later.

## Code style

- Format all Go sources with `gofmt`; run `make fmt` before committing.
- Every source file begins with the MIT SPDX header and the copyright notice
  (copy it from any existing file).
- Comments, documentation and commit messages are written in English.
- Commit messages follow `type(scope): description`
  (for example `feat(packet): implement header codec`).
- Prefer the standard library in the library core. Keep external dependencies
  out of `errors`, `types`, `packet`, `crypto`, `protocol`, `transport` and
  `legacy`. Only `yang`, `client`, `server`, `cmd/tacacs-cli` and the tests
  may pull in third-party modules.

## Logging convention

The library core logs through the `types.Logger` interface (the default is
`types.NopLogger()`). The interface is signature-compatible with a subset of
`*slog.Logger`: callers pass `msg string, args ...any` where `args` are
alternating key/value pairs, and levels use `slog.Level`
(`slog.LevelDebug`, `slog.LevelInfo`, `slog.LevelWarn`, `slog.LevelError`).

Every log call is annotated with a `func` field naming the caller using the
dotted path from the module root (e.g. `packet.Header.Marshal`). Use
`types.WithFunc(logger, name)` as a convenience wrapper — equivalent to
`logger.With("func", name)`.

The `tacacs-cli` tool injects a logrus adapter that satisfies the interface;
library packages (`errors`, `types`, `packet`, `crypto`, `protocol`,
`transport`, `legacy`) stay free of any logging dependency.

When the log level is Debug, log the full upstream request and response,
including headers and bodies (hex-dumped for binary protocols).

## Testing

- Unit tests use [testify](https://github.com/stretchr/testify).
- The coverage target is ≥ 90% per package; check with `make cover`.
- Integration tests run end-to-end client/server loops over TCP and TLS.

## Pull requests

- Open a pull request against `main`.
- Keep changes focused; one logical change per pull request.
- Ensure `gofmt -l .`, `go vet ./...` and `go test ./...` are clean before
  requesting review.

## Security

Changes to authentication, cryptography or TLS code require special care.
Note any security impact in your pull request description, and never log shared
secrets, keys or tokens.
