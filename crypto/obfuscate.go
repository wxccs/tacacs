// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 The tacacs authors.
//
// This library is free software: you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library. If not, see <https://www.gnu.org/licenses/>.

package crypto

import (
	"crypto/md5"
	"encoding/binary"
)

// md5DigestSize is the size in bytes of an MD5 digest.
const md5DigestSize = 16

// pseudoPad generates the obfuscation pad of length len(body) per RFC 8907
// §4.5. The pad is the concatenation of MD5 digests:
//
//	MD5_1   = MD5(session_id[4] || key || version[1] || seq_no[1])
//	MD5_n   = MD5(session_id[4] || key || version[1] || seq_no[1] || MD5_{n-1})
//
// truncated to len(body). The session id is written in network (big-endian)
// byte order; version and seq_no are the raw single header bytes.
func pseudoPad(body []byte, key []byte, sessionID uint32, version, seqNo byte) []byte {
	n := len(body)
	if n == 0 {
		return nil
	}
	// Pre-allocate the base input stream once and reuse it.
	base := make([]byte, 0, 4+len(key)+1+1+md5DigestSize)
	base = binary.BigEndian.AppendUint32(base, sessionID)
	base = append(base, key...)
	base = append(base, version, seqNo)

	pad := make([]byte, 0, n)
	var prev []byte
	for len(pad) < n {
		h := md5.New()
		h.Write(base)
		if prev != nil {
			h.Write(prev)
		}
		digest := h.Sum(nil)
		remaining := min(n-len(pad), md5DigestSize)
		pad = append(pad, digest[:remaining]...)
		prev = digest
	}
	return pad
}

// xorPad XORs body with the pseudo pad in place. Because XOR is symmetric,
// the same operation obfuscates and de-obfuscates.
func xorPad(body []byte, key []byte, sessionID uint32, version, seqNo byte) {
	pad := pseudoPad(body, key, sessionID, version, seqNo)
	for i := range body {
		body[i] ^= pad[i]
	}
}

// Obfuscate XORs the packet body with the MD5 pseudo pad, returning a new
// slice. The header is never obfuscated; the caller passes only the body. An
// empty body returns nil.
//
// Per RFC 8907 §4.5, the header flag TAC_PLUS_UNENCRYPTED_FLAG must be 0 for
// obfuscation to apply. Flag handling is the caller's responsibility; this
// function performs the raw obfuscation.
func Obfuscate(body []byte, key []byte, sessionID uint32, version, seqNo byte) []byte {
	if len(body) == 0 {
		return nil
	}
	out := make([]byte, len(body))
	copy(out, body)
	xorPad(out, key, sessionID, version, seqNo)
	return out
}

// Deobfuscate XORs an obfuscated packet body with the MD5 pseudo pad, returning
// a new slice. This is the inverse of Obfuscate; both use the same XOR pad.
func Deobfuscate(body []byte, key []byte, sessionID uint32, version, seqNo byte) []byte {
	return Obfuscate(body, key, sessionID, version, seqNo)
}

// ObfuscateInPlace obfuscates body in place, modifying the supplied buffer.
func ObfuscateInPlace(body []byte, key []byte, sessionID uint32, version, seqNo byte) {
	xorPad(body, key, sessionID, version, seqNo)
}

// DeobfuscateInPlace de-obfuscates body in place, modifying the supplied buffer.
func DeobfuscateInPlace(body []byte, key []byte, sessionID uint32, version, seqNo byte) {
	xorPad(body, key, sessionID, version, seqNo)
}
