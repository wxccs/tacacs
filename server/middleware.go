// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package server

import (
	"context"
	"fmt"
	"io"
	"runtime/debug"
	"time"

	"github.com/wxccs/tacacs/packet"
	"github.com/wxccs/tacacs/transport"
	"github.com/wxccs/tacacs/types"
)

// Request is the inbound TACACS+ request passed to a Handler. It is the
// middleware-visible view of a single packet: the decoded header, the raw
// (already de-obfuscated) body, the transport Conn, the remote address, and
// the request context.
type Request struct {
	Header packet.Header
	Body   []byte
	Conn   *transport.Conn
	Remote string
	Ctx    context.Context
}

// Response is the outbound side of a request. A Handler encodes and writes a
// reply via Reply, signals a terminal error via ReplyError, or marks the
// connection for termination via Terminate.
type Response interface {
	// Reply encodes body and writes it with the next sequence number. The
	// header's type, session_id, version and flags are echoed from the
	// inbound packet; seq_no is incremented by 1.
	Reply(body packet.Body) error
	// ReplyError writes a header-only TACACS+ error packet (the generic
	// error defined by RFC 8907 §4.2).
	ReplyError() error
	// Header returns the inbound header. Middleware may inspect it to
	// decide logging fields.
	Header() packet.Header
	// Conn returns the underlying transport.Conn, for middleware that
	// needs direct access (e.g. PROXY-aware logging).
	Conn() *transport.Conn
	// Terminate marks the connection for termination after the current
	// Handler returns. ServeConn checks Terminated and exits with Err.
	Terminate(err error)
	// Terminated reports whether Terminate was called.
	Terminated() bool
	// Err returns the error passed to Terminate, or nil.
	Err() error
}

// RequestHandler is the middleware-chain terminal. The Server's dispatch loop
// constructs a Request and Response and calls Handle. Middleware wraps a
// RequestHandler to add cross-cutting behavior (logging, metrics, recovery).
type RequestHandler interface {
	Handle(resp Response, req Request)
}

// RequestHandlerFunc adapts a function to the RequestHandler interface.
type RequestHandlerFunc func(Response, Request)

// Handle implements RequestHandler.
func (f RequestHandlerFunc) Handle(resp Response, req Request) { f(resp, req) }

// Middleware wraps a RequestHandler, returning a new RequestHandler that may
// observe or modify the request and response. Middleware is composed via Chain.
type Middleware func(RequestHandler) RequestHandler

// Chain applies middleware so that the first entry runs outermost. Given
// Chain(h, A, B, C), the execution order is A → B → C → h → C → B → A.
func Chain(h RequestHandler, mw ...Middleware) RequestHandler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// connResponse implements Response over a transport.Conn. It is the default
// Response used by ServeConn.
type connResponse struct {
	conn       *transport.Conn
	header     packet.Header
	terminated bool
	err        error
}

func (r *connResponse) Reply(body packet.Body) error {
	b, err := body.MarshalBinary()
	if err != nil {
		return err
	}
	out := packet.Header{
		Version: r.header.Version, Type: r.header.Type,
		SeqNo: r.header.SeqNo + 1, Flags: r.header.Flags,
		SessionID: r.header.SessionID,
	}
	return r.conn.WritePacket(out, b)
}

func (r *connResponse) ReplyError() error {
	out := packet.ErrorHeader(r.header)
	return r.conn.WritePacket(out, nil)
}

func (r *connResponse) Header() packet.Header { return r.header }
func (r *connResponse) Conn() *transport.Conn { return r.conn }
func (r *connResponse) Terminate(err error)   { r.terminated = true; r.err = err }
func (r *connResponse) Terminated() bool      { return r.terminated }
func (r *connResponse) Err() error            { return r.err }

// handlerAdapter bridges the new Handler interface to the Server's existing
// dispatch methods (handleAuthen/handleAuthor/handleAcct). It is the
// terminal Handler in the middleware chain.
type handlerAdapter struct {
	server *Server
}

// Handle dispatches the request to the appropriate Server method based on
// the packet type. On error it terminates the response so ServeConn exits.
func (a handlerAdapter) Handle(resp Response, req Request) {
	s := a.server
	var err error
	switch req.Header.Type {
	case types.PacketAuthentication:
		err = s.handleAuthen(req.Ctx, req.Conn, req.Header, req.Body)
	case types.PacketAuthorization:
		err = s.handleAuthor(req.Ctx, req.Conn, req.Header, req.Body)
	case types.PacketAccounting:
		err = s.handleAcct(req.Ctx, req.Conn, req.Header, req.Body)
	default:
		err = s.sendGenericError(req.Conn, req.Header)
	}
	if err != nil {
		resp.Terminate(err)
	}
}

// LoggingMiddleware logs each inbound request and its outcome. The logger
// receives a "func" field naming the middleware, per the project's logging
// convention.
func LoggingMiddleware(l types.Logger) Middleware {
	return func(next RequestHandler) RequestHandler {
		return RequestHandlerFunc(func(resp Response, req Request) {
			start := time.Now()
			l.Debug("tacacs: packet received",
				"func", "server.Middleware.Logging",
				"type", req.Header.Type.String(),
				"session_id", req.Header.SessionID,
				"seq_no", req.Header.SeqNo,
				"remote", req.Remote,
			)
			next.Handle(resp, req)
			l.Debug("tacacs: packet handled",
				"func", "server.Middleware.Logging",
				"duration", time.Since(start),
				"terminated", resp.Terminated(),
			)
		})
	}
}

// MetricsMiddleware records packet and outcome counters via the Metrics hook.
func MetricsMiddleware(m Metrics) Middleware {
	return func(next RequestHandler) RequestHandler {
		return RequestHandlerFunc(func(resp Response, req Request) {
			m.IncPacketReceived(req.Header.Type)
			next.Handle(resp, req)
			if resp.Terminated() {
				m.IncPacketInvalid("handler_error")
			}
		})
	}
}

// RecoveryMiddleware recovers from panics in downstream handlers, logs the
// panic with a stack trace, and sends a generic error reply before
// terminating the connection.
func RecoveryMiddleware(l types.Logger) Middleware {
	return func(next RequestHandler) RequestHandler {
		return RequestHandlerFunc(func(resp Response, req Request) {
			defer func() {
				if r := recover(); r != nil {
					l.Error("tacacs: handler panic recovered",
						"func", "server.Middleware.Recovery",
						"err", fmt.Sprint(r),
						"stack", string(debug.Stack()),
					)
					_ = resp.ReplyError()
					resp.Terminate(fmt.Errorf("handler panic: %v", r))
				}
			}()
			next.Handle(resp, req)
		})
	}
}

// RecorderMiddleware records each inbound and outbound packet to w for
// debugging. It writes a timestamped line per packet. This middleware is
// expensive and intended for development only.
func RecorderMiddleware(w io.Writer) Middleware {
	return func(next RequestHandler) RequestHandler {
		return RequestHandlerFunc(func(resp Response, req Request) {
			fmt.Fprintf(w, "%s IN  type=%s session=%d seq=%d body=%d bytes\n",
				time.Now().Format(time.RFC3339Nano),
				req.Header.Type, req.Header.SessionID, req.Header.SeqNo, len(req.Body))
			next.Handle(resp, req)
			fmt.Fprintf(w, "%s OUT terminated=%v\n",
				time.Now().Format(time.RFC3339Nano), resp.Terminated())
		})
	}
}
