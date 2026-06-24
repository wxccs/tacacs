// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package transport

import (
	"bufio"
	"net"

	"github.com/wxccs/tacacs/transport/proxy"
)

// proxyPrefixedConn wraps a net.Conn whose first bytes have already been
// read into a bufio.Reader (e.g. by proxy.ReadHeader). Reads drain the
// bufio.Reader first, then the underlying net.Conn. All other net.Conn
// methods delegate to the embedded net.Conn.
type proxyPrefixedConn struct {
	r *bufio.Reader
	net.Conn
}

func (p *proxyPrefixedConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// AcceptWithProxy wraps a raw server-side connection, first reading a
// PROXY protocol v1 header to recover the real client address. If no
// PROXY header is present, it falls back to the connection's RemoteAddr.
//
// The returned net.Addr is the real client address; pass it to
// SecretProvider.Get and AuthenContext.RemoteAddr so policy decisions
// reflect the end client rather than the load balancer.
//
// On a malformed PROXY header the connection is closed and an error is
// returned.
func AcceptWithProxy(nc net.Conn, mode Mode, secret []byte) (*Conn, net.Addr, error) {
	br := bufio.NewReader(nc)
	realAddr, err := proxy.ReadHeader(br)
	switch err {
	case nil:
		// PROXY header parsed; realAddr is the client.
	case proxy.ErrNoProxyHeader:
		// No PROXY header; fall back to the connection's RemoteAddr.
		realAddr = nc.RemoteAddr()
	default:
		_ = nc.Close()
		return nil, nil, err
	}
	conn := NewConn(&proxyPrefixedConn{r: br, Conn: nc}, mode, secret)
	return conn, realAddr, nil
}
