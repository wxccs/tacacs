// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package proxy

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
)

// v2Sig is the 12-byte binary signature that prefixes every PROXY v2 header.
var v2Sig = [12]byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

const (
	// v2HeaderLen is the fixed prefix: 12-byte signature + ver/cmd + fam/proto
	// + 2-byte address length.
	v2HeaderLen = 16

	v2Version = 0x2 // high nibble of the ver/cmd byte

	v2CmdLocal = 0x0 // connection from the proxy itself (e.g. health check)
	v2CmdProxy = 0x1 // connection on behalf of a real client

	v2FamInet  = 0x1 // AF_INET (high nibble of fam/proto byte)
	v2FamInet6 = 0x2 // AF_INET6

	v2AddrLenInet  = 12 // 4+4 addr + 2+2 port
	v2AddrLenInet6 = 36 // 16+16 addr + 2+2 port
)

// readHeaderV2 parses a PROXY v2 binary header. The first byte (0x0D) has been
// confirmed by ReadHeader but not consumed.
//
// Only the address block is interpreted (per deployment scope): for a PROXY
// command over AF_INET/AF_INET6 the real client TCP address is returned. The
// LOCAL command and non-IP families carry no usable client address, so the
// header is consumed and ErrNoProxyHeader is returned to signal a fall back to
// the connection's RemoteAddr. Any trailing TLV bytes within the advertised
// address length are consumed and ignored.
func readHeaderV2(r *bufio.Reader) (net.Addr, error) {
	hdr := make([]byte, v2HeaderLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	for i := range v2Sig {
		if hdr[i] != v2Sig[i] {
			return nil, ErrMalformedProxy
		}
	}

	verCmd := hdr[12]
	if verCmd>>4 != v2Version {
		return nil, ErrMalformedProxy
	}
	cmd := verCmd & 0x0F
	if cmd != v2CmdLocal && cmd != v2CmdProxy {
		return nil, ErrMalformedProxy
	}

	family := hdr[13] >> 4
	addrLen := binary.BigEndian.Uint16(hdr[14:16])

	// Consume the full advertised address block (address fields + any TLVs).
	addr := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addr); err != nil {
		return nil, err
	}

	// LOCAL connections carry no client address; fall back to RemoteAddr.
	if cmd == v2CmdLocal {
		return nil, ErrNoProxyHeader
	}

	switch family {
	case v2FamInet:
		if len(addr) < v2AddrLenInet {
			return nil, ErrMalformedProxy
		}
		ip := net.IP(append([]byte(nil), addr[0:4]...))
		port := binary.BigEndian.Uint16(addr[8:10])
		return &net.TCPAddr{IP: ip, Port: int(port)}, nil
	case v2FamInet6:
		if len(addr) < v2AddrLenInet6 {
			return nil, ErrMalformedProxy
		}
		ip := net.IP(append([]byte(nil), addr[0:16]...))
		port := binary.BigEndian.Uint16(addr[32:34])
		return &net.TCPAddr{IP: ip, Port: int(port)}, nil
	default:
		// AF_UNSPEC or AF_UNIX: no usable IP client address. The header has
		// been consumed; fall back to the real RemoteAddr.
		return nil, ErrNoProxyHeader
	}
}
