# Operations guide

This guide covers running `tacacs-cli server` in production: transport
security, AAA backends, observability, capacity limits, hot reload and
graceful shutdown. It assumes you have read the [README](../README.md) and
have a working `--config` user/policy file (see [`docs/examples/users.yaml`](examples/users.yaml)).

## Table of contents

- [Transport security](#transport-security)
- [Authentication backends](#authentication-backends)
- [Authorization and accounting](#authorization-and-accounting)
- [Observability](#observability)
- [Capacity and timeouts](#capacity-and-timeouts)
- [Hot reload](#hot-reload)
- [Graceful shutdown](#graceful-shutdown)
- [Multi-NAS: shared secrets and PROXY protocol](#multi-nas-shared-secrets-and-proxy-protocol)
- [Systemd unit example](#systemd-unit-example)

## Transport security

TACACS+ supports two transports; pick one and use it consistently per
deployment.

- **Legacy obfuscated (RFC 8907).** MD5 pseudo-pad body obfuscation. The
  shared secret is the only protection against passive observers. Use only
  on a trusted network where you also control the path (e.g. a management
  VLAN). The shared secret must be high entropy; `testkey` is for dev only.
- **TLS 1.3 (RFC 9887).** Obsoletes body obfuscation: TLS protects the
  entire TACACS+ stream, including headers. **Recommended for any
  deployment that crosses an untrusted network.** Enable with `--tls`
  plus `--server-cert` and `--server-key`. Provide `--ca-cert` to require
  client-certificate authentication on top.

```bash
tacacs-cli server \
  --listen 0.0.0.0 --port 49 \
  --tls --server-cert /etc/tacacs/server.pem --server-key /etc/tacacs/server.key \
  --ca-cert /etc/tacacs/ca.pem \
  --secret "" --config /etc/tacacs/users.yaml
```

> When TLS is enabled the shared secret is unused on the wire but still
> required by the CLI flags (pass any non-empty placeholder). Per-client
> secrets remain useful for legacy clients on the same listener — configure
> a [SecretProvider](#multi-nas-shared-secrets-and-proxy-protocol).

## Authentication backends

`--auth-backend` selects where credentials are verified. Authorization rules
and accounting always come from `--config`; only credential verification is
delegated.

### `local` (default)

bcrypt-hashed passwords from `--config`. The right choice when the user
database is small and changes infrequently. See
[`docs/examples/users.yaml`](examples/users.yaml) for the schema.

### `http`

Delegates verification to an external HTTPS endpoint via JSON. Use this as
the universal escape hatch for identity systems without a native backend
(LDAP-backed web services, OAuth token introspection bridges, bespoke
directories).

```bash
tacacs-cli server --config /etc/tacacs/users.yaml \
  --auth-backend http --auth-http-url https://idp.example.com/tacacs/verify
```

The endpoint receives `POST` with
`{"username":"...","password":"...","authen_type":"pap"}` and must reply
`200` with `{"authenticated":true|false}`. Any non-2xx status, transport
error or malformed body is surfaced as an authentication ERROR (never a
silent fail) so misconfiguration cannot silently lock users out.

Security: the endpoint **MUST** be `https`. `--auth-http-insecure` permits a
plain-`http` endpoint and is intended only for a trusted localhost sidecar;
the password travels in the request body, never in the URL or logs.

### `ldap`

Search-then-bind against an LDAP directory (OpenLDAP, 389-DS, Active
Directory). Use this when credentials already live in a central directory.

```bash
tacacs-cli server --config /etc/tacacs/users.yaml \
  --auth-backend ldap \
  --auth-ldap-url ldaps://dir.example.com:636 \
  --auth-ldap-binddn cn=tacacs-svc,ou=service,dc=example,dc=com \
  --auth-ldap-bindpw "$LDAP_BIND_PW" \
  --auth-ldap-basedn ou=people,dc=example,dc=com \
  --auth-ldap-filter '(sAMAccountName=%s)'
```

Security:

- `ldaps://` (implicit TLS) is the default expectation. `ldap://` requires
  either `--auth-ldap-starttls` or `--auth-ldap-insecure`; the latter sends
  the bind password in clear and is for trusted local directories only.
- **Empty passwords are rejected before the directory is contacted.** Many
  LDAP servers treat an empty-password bind as an anonymous
  "unauthenticated bind" that SUCCEEDS — accepting it would let any user
  in without a password. The authenticator refuses to forward empty
  credentials.
- The username is escaped with `ldap.EscapeFilter` before interpolation to
  prevent LDAP filter injection. Keep the `%s` placeholder in
  `--auth-ldap-filter`; do not interpolate the username yourself.

### `pam`

Delegates to the host PAM stack via cgo. Use this when credentials should
be checked against local system accounts or any module already wired into
PAM (pam_unix, pam_ldap, pam_google_authenticator, ...).

```bash
tacacs-cli server --config /etc/tacacs/users.yaml \
  --auth-backend pam --auth-pam-service tacacs
```

Build constraints: requires **Linux with cgo**. On other platforms (or
when cgo is disabled) the constructor returns an error. Cross-compile with
`CGO_ENABLED=1 GOOS=linux go build`.

Security:

- Create a **dedicated** `/etc/pam.d/tacacs` service file scoped to
  exactly the modules you intend. Do not reuse `login` or `sshd`, which
  pull in unrelated modules (session setup, motd, keyring).
- The PAM stack runs with the privileges of the server process. Run the
  server as a dedicated unprivileged user that can read only its own
  config and the PAM service files it needs.
- Only PAP and the interactive ASCII flow are supported: PAM needs a
  cleartext password to feed the conversation. CHAP/MS-CHAP cannot work.

## Authorization and accounting

Authorization is independent of the auth backend: it always consults the
structured rules in `--config` (groups, services, per-user commands) and
falls back to the legacy `policy.allow-commands` / `policy.deny-commands`
glob patterns. See [`docs/examples/users.yaml`](examples/users.yaml).

Accounting is opt-in:

- `--accounting-log /var/log/tacacs/accounting.jsonl` appends JSONL records.
- `--syslog` writes to syslog instead and takes precedence when both are
  set (avoids double-write surprises).
- Without either, accounting requests are acknowledged but not persisted.

```bash
tacacs-cli server --config /etc/tacacs/users.yaml \
  --accounting-log /var/log/tacacs/accounting.jsonl
```

Rotate the accounting log out-of-band (e.g. `logrotate` with `copytruncate`);
the server keeps the file open for the lifetime of the process.

## Observability

### Prometheus metrics

`--metrics-addr :8080` starts an HTTP server exposing `/metrics`. Scrape it
with Prometheus; the relevant series:

| Metric | Labels | What it tells you |
|---|---|---|
| `tacacs_packets_received_total` | `type` | inbound packet count by type |
| `tacacs_packets_invalid_total` | `reason` | decode/flag-policy failures |
| `tacacs_authen_status_total` | `authen_type`, `status` | auth replies by type and outcome |
| `tacacs_author_status_total` | `status` | authorization outcomes |
| `tacacs_acct_status_total` | `status` | accounting outcomes |
| `tacacs_aaa_handler_latency_seconds` | `phase` | histogram of AAA handler wall time |
| `tacacs_secret_lookups_total` | `hit` | SecretProvider hit/miss |
| `tacacs_connections_accepted_total` | — | connections dispatched for service |
| `tacacs_connections_rejected_total` | `reason` | pre-service rejections (e.g. `max_conns`) |
| `tacacs_accept_errors_total` | — | transient Accept errors that triggered backoff |
| `tacacs_session_duration_seconds` | — | session wall-clock histogram |
| `tacacs_sessions_active` | — | gauge of in-flight sessions |

Alert suggestions:

- `rate(tacacs_authen_status_total{status="fail"}[5m])` spikes → credential
  stuffing or a misconfigured NAS.
- `rate(tacacs_connections_rejected_total{reason="max_conns"}[5m]) > 0` →
  raise `--max-conns` or investigate a connection leak.
- `rate(tacacs_accept_errors_total[5m]) > 0` → transient listener errors
  (EMFILE, etc.). Check fd limits.
- `tacacs_sessions_active` near `--max-conns` → capacity pressure.

### Logging

The server uses `log/slog` via a `logrus` adapter. `--debug` raises the
level; otherwise INFO. Each log line carries a `func` field naming the
calling function (e.g. `cmd.tacacs-cli.runServer`), per the project logging
convention. Secrets and passwords are never logged.

## Capacity and timeouts

| Flag | Default | Effect |
|---|---|---|
| `--max-conns` | 4096 | hard cap on concurrent connections. New connections beyond this are rejected (logged + counted in `tacacs_connections_rejected_total{reason="max_conns"}`). 0 = unlimited (not recommended in production). |
| `--read-timeout` | 30s | per-packet body read timeout. Protects against slowloris-style clients that open a connection and stall mid-packet. 0 disables. |
| `--idle-timeout` | 0 (off) | how long to wait for the next packet on an idle connection. Set to e.g. `5m` to reclaim idle sessions; NAS implementations typically keep connections short-lived. |
| `--shutdown-timeout` | 10s | how long to drain in-flight connections on SIGINT/SIGTERM before force-closing. |

Sizing guidance:

- One TACACS+ connection carries a single session with a single-byte
  `seq_no` (ceiling 255). Real NAS implementations open a fresh connection
  per AAA exchange, so concurrent-connection count ≈ concurrent AAA
  exchanges. Size `--max-conns` to your peak concurrent NAS count plus
  headroom.
- Each connection holds a goroutine and a small read buffer; idle
  connections cost ~10 KiB resident. At `--max-conns 4096` the resident
  ceiling from connection state alone is ~40 MiB.
- The server is CPU-bound on MD5 obfuscation per packet. See
  [`docs/load-test.md`](load-test.md) for measured throughput.

File descriptor limits: raise `ulimit -n` above `--max-conns` plus a safety
margin (the metrics server, accounting log, and stdlib internals consume a
few dozen fds). See the [systemd unit](#systemd-unit-example) below for
`LimitNOFILE`.

## Hot reload

`--watch-config` watches `--config` for changes and reloads the user
database and authorization rules without restarting. The reload is atomic
per file (a rename or replace is observed); a parse failure is logged and
the previous rules keep serving.

- Only `UserConfig` (the `users.yaml` schema) is watchable. YANG
  server-list reload is not supported.
- When `--auth-backend` is not `local`, the bcrypt user database is not
  used for verification, so user-side reloads still refresh authorization
  rules but do not affect authentication.
- Authorization rule reload recompiles the regex set; an invalid regex in
  the new file aborts the reload (the previous set keeps serving) and is
  logged at WARN.

## Graceful shutdown

SIGINT/SIGTERM triggers:

1. The listener is closed; no new connections are accepted.
2. The metrics HTTP server is shut down.
3. In-flight connections are given `--shutdown-timeout` to drain naturally.
4. On timeout, remaining connection contexts are cancelled and their
   sockets are force-closed (a blocking `ReadPacket` does not observe
   context on its own, so the socket close is what unblocks it).

The exit code is 0 if all connections drained within the timeout, non-zero
otherwise. The `tacacs_connections_rejected_total` and
`tacacs_accept_errors_total` counters are not affected by shutdown.

## Multi-NAS: shared secrets and PROXY protocol

When multiple NAS devices share one server but use different shared
secrets, configure a `SecretProvider` in `--config` instead of a single
`--secret`. The provider maps the peer IP to a secret (and optionally a
transport mode) at connection time.

- **PrefixSecretProvider** — CIDR-based: one secret per NAS subnet.
  Suitable when NAS addresses are stable and known.
- **DNSSecretProvider** — forward-DNS based: resolve configured hostnames
  to an IP set at construction and on `Refresh`. Use this when NAS
  addresses are dynamic (DHCP, autoscaling). The provider never consults
  PTR records (spoofable) and never does DNS on the connection hot path:
  refresh is explicit, with stale-while-revalidate on per-host failure.

When the server sits behind a TCP load balancer (HAProxy, Envoy, AWS NLB,
Cloudflare Spectrum), enable **PROXY protocol v1 or v2** on the listener
so the server sees the real NAS address for secret lookup and accounting.
The server auto-detects v1 (text) vs v2 (binary) by the first byte and
falls back to `RemoteAddr` when no PROXY header is present. Configure the
upstream load balancer to send the PROXY header on every connection.

See the YANG config examples in [`docs/examples/`](examples) for
`secret-provider` configuration.

## Systemd unit example

```ini
# /etc/systemd/system/tacacs.service
[Unit]
Description=TACACS+ server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=tacacs
Group=tacacs
ExecStart=/usr/local/bin/tacacs-cli server \
    --listen 0.0.0.0 --port 49 \
    --tls --server-cert /etc/tacacs/server.pem --server-key /etc/tacacs/server.key \
    --ca-cert /etc/tacacs/ca.pem \
    --config /etc/tacacs/users.yaml \
    --metrics-addr :8080 \
    --accounting-log /var/log/tacacs/accounting.jsonl \
    --max-conns 4096 --read-timeout 30s --idle-timeout 5m \
    --shutdown-timeout 15s
Restart=on-failure
RestartSec=2s

# Raise fd limit above --max-conns.
LimitNOFILE=8192

# Hardening.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/log/tacacs
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
```

Run as a dedicated user; grant it read access to the cert/key files and
write access to the accounting log directory only.
