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

package server

import (
	"context"
	"net"

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
}

// Server accepts connections and dispatches packets to the Handler.
type Server struct {
	cfg    Config
	policy crypto.Policy
	// sessions maps a session_id to the START context accumulated for an
	// interactive authentication, so a CONTINUE can be matched to its START.
	sessions map[uint32]AuthenStart
}

// New creates a Server.
func New(cfg Config) *Server {
	return &Server{
		cfg:      cfg,
		policy:   crypto.Policy{AllowUnencrypted: cfg.AllowUnencrypted || cfg.Mode == transport.ModeTLS},
		sessions: make(map[uint32]AuthenStart),
	}
}

// ServeConn drives a single connection to completion, reading packets and
// writing responses until the connection closes or an error occurs.
func (s *Server) ServeConn(ctx context.Context, c *transport.Conn) error {
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
		if err := s.checkFlags(hdr); err != nil {
			// Flag policy violation: send a typed error and terminate.
			if perr := s.sendError(c, hdr); perr != nil {
				return perr
			}
			return err
		}
		// TLS forces the unencrypted flag; legacy bodies are already de-obfuscated
		// by Conn.ReadPacket.
		if err := s.dispatch(ctx, c, hdr, body); err != nil {
			return err
		}
	}
}

// checkFlags enforces the flag policy. Under TLS the unencrypted flag MUST be
// set; under legacy, the flag must not be set unless explicitly allowed.
func (s *Server) checkFlags(hdr packet.Header) error {
	flagSet := hdr.Flags.Has(types.FlagUnencrypted)
	if s.cfg.Mode == transport.ModeTLS {
		return transport.EnforceTLSFlagPolicy(flagSet)
	}
	return s.policy.CheckUnencryptedFlag(flagSet)
}

func (s *Server) dispatch(ctx context.Context, c *transport.Conn, hdr packet.Header, body []byte) error {
	switch hdr.Type {
	case types.PacketAuthentication:
		return s.handleAuthen(ctx, c, hdr, body)
	case types.PacketAuthorization:
		return s.handleAuthor(ctx, c, hdr, body)
	case types.PacketAccounting:
		return s.handleAcct(ctx, c, hdr, body)
	default:
		return s.sendGenericError(c, hdr)
	}
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
		s.sessions[hdr.SessionID] = start
	} else {
		// Restore the START context so the handler has the user and service for
		// an interactive CONTINUE.
		start = s.sessions[hdr.SessionID]
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
		delete(s.sessions, hdr.SessionID)
		return s.sendAuthenError(c, hdr, err)
	}
	if dec.Status == types.AuthenStatusPass || dec.Status == types.AuthenStatusFail || dec.Status == types.AuthenStatusError {
		delete(s.sessions, hdr.SessionID)
	}
	reply := packet.AuthenReply{
		Status: dec.Status, Flags: dec.Flags, ServerMsg: dec.ServerMsg, Data: string(dec.Data),
	}
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
