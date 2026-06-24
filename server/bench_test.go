// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package server_test

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/wxccs/tacacs/client"
	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/transport"
	"github.com/wxccs/tacacs/types"
)

// benchHandler is a minimal AAA handler with constant-time decisions so the
// benchmark measures protocol framing, obfuscation and dispatch rather than
// backend work.
type benchHandler struct{}

func (benchHandler) Authenticate(_ context.Context, ac server.AuthenContext, cont *server.AuthenContinue) (server.AuthenDecision, error) {
	if cont == nil && ac.Start.Type == types.AuthenTypePAP {
		if string(ac.Start.Data) == "secret123" {
			return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
		}
	}
	return server.AuthenDecision{Status: types.AuthenStatusFail}, nil
}

func (benchHandler) Authorize(_ context.Context, _ server.AuthorContext) (server.AuthorDecision, error) {
	return server.AuthorDecision{Status: types.AuthorStatusPassAdd}, nil
}

func (benchHandler) Account(_ context.Context, _ server.AcctContext) (server.AcctDecision, error) {
	return server.AcctDecision{Status: types.AcctStatusSuccess}, nil
}

// benchServer starts an accept loop that serves every inbound connection until
// the listener is closed. Returns the dial address.
func benchServer(b *testing.B) string {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	b.Cleanup(func() { _ = ln.Close() })
	secret := []byte("sharedkey")
	srv := server.New(server.Config{Handler: benchHandler{}, Secret: secret, Mode: transport.ModeLegacy})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conn := transport.Accept(c, transport.ModeLegacy, secret)
			go func() { _ = srv.ServeConn(context.Background(), conn) }()
		}
	}()
	return fmt.Sprintf("127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port)
}

// benchPerConn runs fn once per iteration on a freshly dialed connection.
// TACACS+ pins a single-byte seq_no to a session, so a connection cannot host
// an arbitrary number of AAA exchanges. Measuring per-connection includes the
// TCP handshake + session-key derivation, which is the realistic cost a NAS
// pays when it opens a dedicated session per request. Pass -benchtime=100x to
// keep the ephemeral-port count bounded.
func benchPerConn(
	b *testing.B,
	addr string,
	secret []byte,
	fn func(cl *client.Client) error,
) {
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := transport.Dial(ctx, "tcp", addr, secret)
		if err != nil {
			b.Fatalf("dial: %v", err)
		}
		cl, err := client.New(conn)
		if err != nil {
			b.Fatalf("client.New: %v", err)
		}
		err = fn(cl)
		_ = conn.Close()
		if err != nil {
			b.Fatalf("iter %d: %v", i, err)
		}
	}
}

// BenchmarkE2EAuthenticatePAP measures a full PAP authentication round-trip
// on a fresh connection: TCP dial, session key derivation, obfuscated
// START/REPLY exchange and handler dispatch.
func BenchmarkE2EAuthenticatePAP(b *testing.B) {
	addr := benchServer(b)
	benchPerConn(b, addr, []byte("sharedkey"), func(cl *client.Client) error {
		reply, err := cl.Authenticate(context.Background(), client.AuthenRequest{
			Action: types.AuthenLogin, Type: types.AuthenTypePAP, Service: types.AuthenServiceLogin,
			User: "alice", Data: []byte("secret123"),
		}, nil)
		if err != nil {
			return err
		}
		if reply.Status != types.AuthenStatusPass {
			return fmt.Errorf("status = %v, want PASS", reply.Status)
		}
		return nil
	})
}

// BenchmarkE2EAuthorize measures a full authorization round-trip on a fresh
// connection.
func BenchmarkE2EAuthorize(b *testing.B) {
	addr := benchServer(b)
	benchPerConn(b, addr, []byte("sharedkey"), func(cl *client.Client) error {
		reply, err := cl.Authorize(context.Background(), client.AuthorRequest{
			Method:  types.AuthenMethodTacacsPlus,
			User:    "alice",
			Service: types.AuthenServiceLogin,
			Args:    []types.Argument{{Name: "cmd", Value: "show"}},
		})
		if err != nil {
			return err
		}
		if reply.Status != types.AuthorStatusPassAdd {
			return fmt.Errorf("status = %v, want PASS_ADD", reply.Status)
		}
		return nil
	})
}

// BenchmarkE2EAccount measures a full accounting round-trip on a fresh
// connection.
func BenchmarkE2EAccount(b *testing.B) {
	addr := benchServer(b)
	benchPerConn(b, addr, []byte("sharedkey"), func(cl *client.Client) error {
		reply, err := cl.Account(context.Background(), client.AcctRequest{
			Flags:   types.AcctFlagStop,
			Method:  types.AuthenMethodTacacsPlus,
			User:    "alice",
			Service: types.AuthenServiceLogin,
			Args:    []types.Argument{{Name: "task_id", Value: "1"}},
		})
		if err != nil {
			return err
		}
		if reply.Status != types.AcctStatusSuccess {
			return fmt.Errorf("status = %v, want SUCCESS", reply.Status)
		}
		return nil
	})
}
