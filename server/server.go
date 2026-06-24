// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package server

import (
	"context"
	"net"
	"time"

	"github.com/wxccs/tacacs/crypto"
	"github.com/wxccs/tacacs/errors"
	"github.com/wxccs/tacacs/packet"
	"github.com/wxccs/tacacs/transport"
	"github.com/wxccs/tacacs/types"
)

// Config configures a Server.
type Config struct {
	// Handler makes the AAA policy decisions.
	Handler Handler
	// Secret is the shared key for MD5 obfuscation (legacy TCP only).
	Secret []byte
	// Mode is the transport mode (legacy or TLS).
	Mode transport.Mode
	// AllowUnencrypted permits TAC_PLUS_UNENCRYPTED_FLAG on legacy connections
	// (RFC 8907 §10.5.2). Defaults to false.
	AllowUnencrypted bool
	// SessionTTL is the idle TTL for authentication sessions. A ttl <= 0
	// falls back to a 5-minute default. Sessions idle past the TTL are
	// evicted by a background sweep goroutine.
	SessionTTL time.Duration
	// Metrics receives observability observations. A nil value falls back to
	// NopMetrics, so the Server is silent by default.
	Metrics Metrics
	// SecretProvider selects the shared secret and transport mode for an
	// incoming connection based on the client's remote address. When nil,
	// the Server uses StaticSecret{Secret, Mode} (the original single-secret
	// behavior). Set a PrefixSecretProvider for multi-NAS deployments.
	SecretProvider SecretProvider
	// Middleware is an ordered list of middleware applied to the dispatch
	// chain. The first entry runs outermost. When nil, the Server dispatches
	// directly to the Handler with no middleware.
	Middleware []Middleware
	// ReadTimeout bounds the time to read a single packet body once its header
	// has arrived, defending against a peer that dribbles a body slowly. A
	// value <= 0 disables the bound (the default, preserving prior behavior).
	ReadTimeout time.Duration
	// IdleTimeout bounds the wait for the next packet on a connection,
	// defending against idle/slow-loris connections. A value <= 0 disables the
	// bound (the default). Single-connection deployments (RFC 8907 §4.3) that
	// keep a connection open between sessions may prefer a generous value or 0.
	IdleTimeout time.Duration
}

// Server accepts connections and dispatches packets to the Handler.
type Server struct {
	cfg    Config
	policy crypto.Policy
	// sessions tracks interactive authentication sessions by SessionID so a
	// CONTINUE can be matched to its START. It is concurrency-safe: each
	// accepted connection runs in its own goroutine and all share this map.
	sessions *sessionManager
	// handler is the terminal RequestHandler (a handlerAdapter wrapping
	// Config.Handler) composed with Config.Middleware via Chain.
	handler RequestHandler
	// sweepCtx / sweepCancel drive the background session-TTL sweeper.
	sweepCtx    context.Context
	sweepCancel context.CancelFunc
}

// New creates a Server and starts a background goroutine that evicts idle
// sessions past Config.SessionTTL. Callers should call Close to stop the
// sweeper when the Server is no longer in use; failing to do so leaks the
// goroutine.
func New(cfg Config) *Server {
	if cfg.Metrics == nil {
		cfg.Metrics = NopMetrics()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		cfg:         cfg,
		policy:      crypto.Policy{AllowUnencrypted: cfg.AllowUnencrypted || cfg.Mode == transport.ModeTLS},
		sessions:    newSessionManager(cfg.SessionTTL, cfg.Metrics),
		sweepCtx:    ctx,
		sweepCancel: cancel,
	}
	s.handler = Chain(RequestHandler(handlerAdapter{server: s}), cfg.Middleware...)
	go s.sessions.SweepLoop(ctx, 0)
	return s
}

// Close stops the background session sweeper. It is the caller's
// responsibility to ensure no further calls to ServeConn are made after Close
// returns. In-flight ServeConn goroutines are not interrupted; they exit when
// their connections close or their contexts cancel.
func (s *Server) Close() error {
	s.sweepCancel()
	return nil
}

// secretProvider returns the configured SecretProvider, defaulting to a
// StaticSecret built from Config.Secret and Config.Mode.
func (s *Server) secretProvider() SecretProvider {
	if s.cfg.SecretProvider != nil {
		return s.cfg.SecretProvider
	}
	return StaticSecret{Secret: s.cfg.Secret, Mode: s.cfg.Mode}
}

// AcceptConn wraps a raw server-side net.Conn using the SecretProvider and
// serves it to completion. It is the recommended entry point when
// Config.SecretProvider is set; for single-secret deployments, callers may
// still use transport.Accept + ServeConn directly.
//
// On a SecretProvider error the connection is closed without sending any
// TACACS+ reply.
func (s *Server) AcceptConn(ctx context.Context, nc net.Conn) error {
	sp := s.secretProvider()
	sc, err := sp.Get(ctx, nc.RemoteAddr())
	if err != nil {
		s.cfg.Metrics.IncSecretLookup(false)
		_ = nc.Close()
		return err
	}
	s.cfg.Metrics.IncSecretLookup(true)
	conn := transport.NewConn(nc, sc.Mode, sc.Secret)
	return s.ServeConn(ctx, conn)
}

// ServeConn drives a single connection to completion, reading packets and
// writing responses until the connection closes or an error occurs.
func (s *Server) ServeConn(ctx context.Context, c *transport.Conn) error {
	if s.cfg.ReadTimeout > 0 || s.cfg.IdleTimeout > 0 {
		c.SetTimeouts(s.cfg.IdleTimeout, s.cfg.ReadTimeout)
	}
	var connFlags types.HeaderFlags
	first := true
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		hdr, body, err := c.ReadPacket()
		if err != nil {
			return err
		}
		if err := s.checkFlags(c, hdr); err != nil {
			// Flag policy violation: send a typed error and terminate.
			if perr := s.sendError(c, hdr); perr != nil {
				return perr
			}
			return err
		}
		if first {
			// Record the flags observed on the first packet. All subsequent
			// packets on this connection MUST carry the same flags (RFC 8907
			// §4.3): mixing encrypted and unencrypted bodies on the same
			// connection is a protocol violation.
			connFlags = hdr.Flags
			first = false
		} else if hdr.Flags != connFlags {
			s.cfg.Metrics.IncPacketInvalid("flag_mismatch")
			return s.sendGenericError(c, hdr)
		}
		// TLS forces the unencrypted flag; legacy bodies are already de-obfuscated
		// by Conn.ReadPacket.
		resp := &connResponse{conn: c, header: hdr}
		req := Request{
			Header: hdr, Body: body, Conn: c,
			Remote: remoteAddr(c), Ctx: ctx,
		}
		s.handler.Handle(resp, req)
		if resp.Terminated() {
			return resp.Err()
		}
	}
}

// checkFlags enforces the per-packet flag policy. Under TLS the unencrypted
// flag MUST be set; under legacy, the flag must not be set unless explicitly
// allowed. The mode is read from the Conn (not Config.Mode) so that a
// SecretProvider returning a per-connection mode is honored.
func (s *Server) checkFlags(c *transport.Conn, hdr packet.Header) error {
	flagSet := hdr.Flags.Has(types.FlagUnencrypted)
	if c.Mode() == transport.ModeTLS {
		return transport.EnforceTLSFlagPolicy(flagSet)
	}
	return s.policy.CheckUnencryptedFlag(flagSet)
}

func (s *Server) handleAuthen(ctx context.Context, c *transport.Conn, hdr packet.Header, body []byte) error {
	// The client always sends odd sequence numbers (1, 3, 5, ...). The first
	// packet of a session is a START (seq_no 1); subsequent client packets are
	// CONTINUE messages. Server replies are even and are not routed here.
	isStart := hdr.SeqNo == 1

	var cont *AuthenContinue
	var start AuthenStart
	if isStart {
		var st packet.AuthenStart
		if err := st.UnmarshalBinary(body); err != nil {
			return s.sendGenericError(c, hdr)
		}
		start = AuthenStart{
			Action: st.Action, PrivLvl: st.PrivLvl, Type: st.Type, Service: st.Service,
			User: st.User, Port: st.Port, RemAddr: st.RemAddr, Data: []byte(st.Data),
		}
		// Register a new session. If a session with this id already exists
		// (e.g. client reused a SessionID), it is replaced.
		s.sessions.Set(hdr.SessionID, &sessionContext{
			start:      start,
			flags:      hdr.Flags,
			remoteAddr: remoteAddr(c),
		})
	} else {
		// Restore the START context so the handler has the user and service for
		// an interactive CONTINUE. An unknown SessionID is a protocol
		// violation (CONTINUE without a preceding START).
		sctx, ok := s.sessions.Get(hdr.SessionID)
		if !ok {
			return s.sendGenericError(c, hdr)
		}
		// Validate the sequence number: the client must send lastOutboundSeq+1
		// next (RFC 8907 §11). A violation terminates the session.
		if err := ValidateNextSeqNo(hdr.SeqNo, sctx.lastOutboundSeq); err != nil {
			s.sessions.Delete(hdr.SessionID)
			s.cfg.Metrics.IncPacketInvalid("seq_no")
			return s.sendGenericError(c, hdr)
		}
		start = sctx.start
		var ct packet.AuthenContinue
		if err := ct.UnmarshalBinary(body); err != nil {
			return s.sendGenericError(c, hdr)
		}
		cont = &AuthenContinue{UserMsg: ct.UserMsg, Data: []byte(ct.Data), Flags: ct.Flags}
	}

	dec, err := s.cfg.Handler.Authenticate(ctx, AuthenContext{
		SessionID: hdr.SessionID, SeqNo: hdr.SeqNo, Start: start,
		RemoteAddr: remoteAddr(c),
	}, cont)
	if err != nil {
		s.sessions.Delete(hdr.SessionID)
		return s.sendAuthenError(c, hdr, err)
	}
	if dec.Status == types.AuthenStatusPass || dec.Status == types.AuthenStatusFail || dec.Status == types.AuthenStatusError {
		s.sessions.Delete(hdr.SessionID)
	} else {
		// Non-terminal (GETUSER/GETPASS/GETDATA): advance the lastOutboundSeq
		// so the next inbound CONTINUE can be validated.
		s.sessions.Update(hdr.SessionID, func(sctx *sessionContext) {
			sctx.lastOutboundSeq = hdr.SeqNo + 1
		})
	}
	reply := packet.AuthenReply{
		Status: dec.Status, Flags: dec.Flags, ServerMsg: dec.ServerMsg, Data: string(dec.Data),
	}
	s.cfg.Metrics.IncAuthenStatus(dec.Status)
	rb, err := reply.MarshalBinary()
	if err != nil {
		return s.sendGenericError(c, hdr)
	}
	return s.writeReply(c, hdr, rb)
}

func (s *Server) handleAuthor(ctx context.Context, c *transport.Conn, hdr packet.Header, body []byte) error {
	var req packet.AuthorRequest
	if err := req.UnmarshalBinary(body); err != nil {
		return s.sendGenericError(c, hdr)
	}
	args := make([]types.Argument, 0, len(req.Args))
	for _, a := range req.Args {
		parsed, perr := types.ParseArgument(a)
		if perr != nil {
			return s.sendAuthorError(c, hdr)
		}
		args = append(args, parsed)
	}
	dec, err := s.cfg.Handler.Authorize(ctx, AuthorContext{
		SessionID: hdr.SessionID, SeqNo: hdr.SeqNo, Method: req.Method, PrivLvl: req.PrivLvl,
		Type: req.Type, Service: req.Service, User: req.User, Port: req.Port, RemAddr: req.RemAddr,
		Args: args, RemoteAddr: remoteAddr(c),
	})
	if err != nil {
		return s.sendAuthorError(c, hdr)
	}
	reply := packet.AuthorReply{Status: dec.Status, ServerMsg: dec.ServerMsg}
	for _, a := range dec.Args {
		reply.Args = append(reply.Args, a.String())
	}
	s.cfg.Metrics.IncAuthorStatus(dec.Status)
	rb, err := reply.MarshalBinary()
	if err != nil {
		return s.sendGenericError(c, hdr)
	}
	return s.writeReply(c, hdr, rb)
}

func (s *Server) handleAcct(ctx context.Context, c *transport.Conn, hdr packet.Header, body []byte) error {
	var req packet.AcctRequest
	if err := req.UnmarshalBinary(body); err != nil {
		return s.sendGenericError(c, hdr)
	}
	if rec := types.AcctFlags(req.Flags).Record(); rec == types.AcctRecordInvalid {
		// Invalid flag combination: server MUST respond ERROR.
		return s.sendAcctError(c, hdr, errors.ErrInvalidArgument)
	}
	args := make([]types.Argument, 0, len(req.Args))
	for _, a := range req.Args {
		parsed, perr := types.ParseArgument(a)
		if perr != nil {
			return s.sendAcctError(c, hdr, perr)
		}
		args = append(args, parsed)
	}
	dec, err := s.cfg.Handler.Account(ctx, AcctContext{
		SessionID: hdr.SessionID, SeqNo: hdr.SeqNo, Flags: req.Flags, Method: req.Method,
		PrivLvl: req.PrivLvl, Type: req.Type, Service: req.Service, User: req.User, Port: req.Port,
		RemAddr: req.RemAddr, Args: args, RemoteAddr: remoteAddr(c),
	})
	if err != nil {
		return s.sendAcctError(c, hdr, err)
	}
	reply := packet.AcctReply{Status: dec.Status, ServerMsg: dec.ServerMsg}
	s.cfg.Metrics.IncAcctStatus(dec.Status)
	rb, err := reply.MarshalBinary()
	if err != nil {
		return s.sendGenericError(c, hdr)
	}
	return s.writeReply(c, hdr, rb)
}

// writeReply encodes a reply body with the next (even) sequence number.
func (s *Server) writeReply(c *transport.Conn, in packet.Header, body []byte) error {
	out := packet.Header{
		Version: in.Version, Type: in.Type, SeqNo: in.SeqNo + 1, Flags: in.Flags,
		SessionID: in.SessionID,
	}
	return c.WritePacket(out, body)
}

func (s *Server) sendAuthenError(c *transport.Conn, in packet.Header, _ error) error {
	reply := packet.AuthenReply{Status: types.AuthenStatusError}
	rb, _ := reply.MarshalBinary()
	return s.writeReply(c, in, rb)
}

func (s *Server) sendAuthorError(c *transport.Conn, in packet.Header) error {
	reply := packet.AuthorReply{Status: types.AuthorStatusError}
	rb, _ := reply.MarshalBinary()
	return s.writeReply(c, in, rb)
}

func (s *Server) sendAcctError(c *transport.Conn, in packet.Header, _ error) error {
	reply := packet.AcctReply{Status: types.AcctStatusError}
	rb, _ := reply.MarshalBinary()
	return s.writeReply(c, in, rb)
}

func (s *Server) sendGenericError(c *transport.Conn, in packet.Header) error {
	out := packet.ErrorHeader(in)
	return c.WritePacket(out, nil)
}

func (s *Server) sendError(c *transport.Conn, in packet.Header) error {
	// For a flag-policy failure we cannot trust the body type, so send the
	// generic header-only error.
	return s.sendGenericError(c, in)
}

// remoteAddr best-effort extracts the peer address from a Conn.
func remoteAddr(c *transport.Conn) string {
	type addrer interface{ RemoteAddr() net.Addr }
	if a, ok := any(c).(addrer); ok {
		return a.RemoteAddr().String()
	}
	return ""
}
