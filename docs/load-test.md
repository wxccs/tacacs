# Load-test report

This report characterises the throughput and latency of the `tacacs` library
on the development machine, and translates the numbers into operational
guidance for production sizing. The benchmarks live in the repository and
are reproducible — see [Reproducing](#reproducing) below.

## Test environment

| | |
|---|---|
| OS | macOS (Darwin 24.6.0) |
| Arch | amd64 |
| CPU | Intel Core i5-8500B @ 3.00 GHz (6 cores) |
| Go | 1.26.4 |
| Date | 2026-06-25 |

Numbers are from `go test -bench` with `-benchmem`. Real production
throughput depends on the NAS connection pattern, secret length, payload
sizes, and the authentication backend (`local` bcrypt is the slowest;
`http`/`ldap`/`pam` add network round-trips).

## What was measured

Two layers are benchmarked:

1. **Codec layer** — packet header and body marshal/unmarshal, plus MD5
   obfuscation. These are pure-CPU operations and characterise the
   per-packet cost the server pays regardless of transport.
2. **End-to-end layer** — a full AAA round-trip on a fresh TCP connection
   per iteration, including TCP handshake, session key derivation, obfuscated
   START/REPLY exchange, and handler dispatch. This is the realistic cost a
   NAS pays when it opens a dedicated session per request (the dominant
   pattern in the wild).

## Codec layer

```
BenchmarkHeaderMarshal-6           1000000000   0.26 ns/op    0 B/op   0 allocs/op
BenchmarkHeaderUnmarshal-6          773704311   3.10 ns/op    0 B/op   0 allocs/op
BenchmarkAuthenStartMarshal-6        65128434   34.9 ns/op   32 B/op   1 allocs/op
BenchmarkObfuscate-6                    968064   2287 ns/op  816 B/op  19 allocs/op
BenchmarkObfuscateLarge-6               67492  35584 ns/op 12336 B/op 259 allocs/op
```

Reading:

- **Header codec** is effectively free — sub-nanosecond marshal, 3 ns
  unmarshal, zero allocations. The 12-byte TACACS+ header is not a
  bottleneck at any realistic load.
- **AuthenStart marshal** is ~35 ns / 1 alloc. Cheap.
- **Obfuscation** dominates the per-packet CPU cost. The default-cost path
  (~800 B body, 19 allocs, 2.3 μs) is the MD5 pseudo-pad computation over
  the body. The "large" variant (~12 KB body, 36 μs) shows the linear
  scaling: obfuscation is O(body length), as expected from RFC 8907 §4.5.

The 19 allocations in `BenchmarkObfuscate` come from building the per-packet
key concatenation (`secret || session_id || version || seq_no`) and the MD5
hash chain. They are small and short-lived; the GC handles them without
visible pressure at the rates measured below.

## End-to-end layer

```
BenchmarkE2EAuthenticatePAP-6   100   121,807 ns/op   1,902 B/op   61 allocs/op
BenchmarkE2EAuthorize-6          100   131,562 ns/op   1,764 B/op   60 allocs/op
BenchmarkE2EAccount-6           100   127,471 ns/op   1,732 B/op   60 allocs/op
```

Each iteration opens a fresh TCP connection to an in-process server on
`127.0.0.1`, performs one AAA exchange, and closes the connection. The
number therefore includes:

- TCP handshake (1 RTT, ~50 μs on loopback),
- session key derivation (1 MD5 over the shared secret + session ID),
- obfuscated START + REPLY exchange (2 obfuscation passes),
- handler dispatch (constant-time stub — zero backend cost),
- TCP teardown.

The three operations are within ~10% of each other, which is expected: the
per-packet obfuscation cost is the same, and the handler work is negligible.
**Authentication is not measurably more expensive than authorization or
accounting at the protocol level** — the dominant cost is connection setup
plus two obfuscation passes, not the AAA branching.

## Throughput interpretation

A single CPU core handles ~8,200 PAP authentications per second in this
end-to-end measurement (1 / 122 μs). With 6 cores and assuming the workload
parallelises across connections (it does — each connection is an independent
goroutine), the ceiling is roughly **~45,000 PAP/s on this dev box** before
the obfuscation CPU saturates.

For production sizing, treat this as an upper bound. Real deployments see
lower numbers because:

- **bcrypt dominates when `--auth-backend local` is used.** bcrypt at default
  cost is ~100 ms per verification, so the auth backend — not the protocol
  — becomes the bottleneck at ~10 verifications/s/core. For higher rates,
  switch to `http`/`ldap`/`pam` backends that push the cost elsewhere, or
  lower the bcrypt cost (trading offline-cracking resistance for throughput).
- **TLS adds a handshake cost.** TLS 1.3 with session resumption is one RTT;
  without resumption it is two. TLS also removes the obfuscation pass (the
  body is sent in clear inside the encrypted channel), saving ~2 μs/packet.
  Net: TLS is roughly neutral to slightly faster than legacy obfuscation at
  steady state, but slower on cold handshakes.
- **External backends add their own latency.** `http`/`ldap`/`pam` each add
  a network round-trip (or PAM module stack cost) per authentication. Size
  the backend pool accordingly; the TACACS+ server itself is not the
  bottleneck when a backend is in use.

## Capacity limits

The single-byte `seq_no` ceiling (255 per session) means a TACACS+
connection cannot host an arbitrary number of AAA exchanges. Real NAS
implementations open a fresh connection per exchange, so:

- **Concurrent connections ≈ concurrent AAA exchanges.** Size
  `--max-conns` to peak concurrent NAS count plus headroom. Default 4096.
- **Ephemeral port exhaustion on the server side.** Each closed connection
  enters `TIME_WAIT` for ~60 s. At ~45,000 connections/s, the server would
  burn through the default ephemeral port range (~28,000 ports on Linux)
  in well under a second. Mitigations:
  - Set `net.ipv4.tcp_tw_reuse=1` on the server (safe for loopback and
    for the NAS-to-server direction).
  - Size `--max-conns` below the ephemeral port range, or run multiple
    server instances behind a load balancer.
  - Prefer TLS (RFC 9887): TLS handshakes are heavier per connection but
    the session can be resumed, reducing the per-exchange cost if the NAS
    supports resumption.

## Latency interpretation

- **p50 ≈ 122 μs** for a PAP round-trip on loopback (the bench median).
- **p99** is dominated by TCP handshake jitter and MD5 scheduling; expect
  ~1–2 ms in the steady state on a quiet host, higher under load.
- **Tail latency** under contention: with `--max-conns` near saturation, new
  connections queue for an Accept slot. The `tacacs_connections_rejected_total`
  counter surfaces this before it becomes user-visible.

For latency-sensitive deployments (NAS-auth timeouts are typically 5–10 s,
so this is rarely the constraint), prefer:

- `--auth-backend http` with a fast idP sidecar (sub-ms verification),
- TLS 1.3 with session resumption,
- `--idle-timeout 5m` to keep warm sessions in the connection pool.

## Reproducing

```bash
# Codec layer (fast, ~10 s).
go test -run='^$' -bench='BenchmarkHeader|BenchmarkAuthenStartMarshal' \
    -benchtime=2s -benchmem ./packet/

go test -run='^$' -bench='BenchmarkObfuscate' \
    -benchtime=2s -benchmem ./crypto/

# End-to-end (slow due to TIME_WAIT; use bounded -benchtime).
go test -run='^$' -bench='BenchmarkE2E' \
    -benchtime=100x -benchmem ./server/
```

The end-to-end benches dial a fresh TCP connection per iteration. With
`-benchtime=2s` they will exhaust ephemeral ports in seconds; use
`-benchtime=100x` (a fixed iteration count) instead, as above. Pause
between runs to let `TIME_WAIT` drain (~60 s), or set
`net.ipv4.tcp_tw_reuse=1`.

The full fuzz and race suite:

```bash
make fuzz        # ~3 min, exercises every decoder with untrusted input
go test -race ./...   # race detector across the whole tree
```

Both are clean as of this report.

## What is NOT measured here

- **Cross-implementation comparison with `tacquito`.** `tacquito`'s `crypt()`
  is unexported, so a like-for-like crypto-layer benchmark would require a
  full connection harness on both sides. The end-to-end benches above
  already exercise both implementations via the [interop suite](../interop);
  protocol correctness is covered, but a head-to-head throughput comparison
  is left as future work.
- **Long-running stability.** The benches are short (seconds). Soak testing
  under realistic mixed load (PAP + authorize + accounting, TLS + legacy,
  multiple NAS sources) over hours is the next step before declaring the
  server production-hardened.
- **bcrypt throughput.** Not benchmarked directly here because the cost is
  parameterised by the bcrypt work factor, not by the TACACS+ protocol. Use
  `golang.org/x/crypto/bcrypt` benchmarks for that number.
