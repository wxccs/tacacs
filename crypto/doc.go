// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
// Package crypto implements the TACACS+ body obfuscation defined by
// RFC 8907 §4.5.
//
// The obfuscation is NOT encryption: it provides no integrity, privacy or
// replay protection (RFC 8907 §10.5.2). New deployments SHOULD use TLS 1.3
// (RFC 9887), which obsoletes this mechanism. This package exists for
// compatibility with legacy non-TLS peers.
//
// The body of a packet (everything after the 12-byte header) is XORed
// bytewise with a pseudo-random pad built from MD5 hashes of the session id,
// the shared secret, the header version byte and the sequence number, each
// subsequent hash appending the previous digest. The header itself is never
// obfuscated.
package crypto
