// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package server

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/wxccs/tacacs/packet"
	"github.com/wxccs/tacacs/transport"
	"github.com/wxccs/tacacs/types"
)

// recordingHandler records the order of Handle calls into a shared buffer for
// verifying middleware composition order.
type recordingHandler struct {
	name string
	log  *bytes.Buffer
}

func (r recordingHandler) Handle(resp Response, req Request) {
	r.log.WriteString(r.name + "|")
}

// makeMiddleware returns a middleware that writes name before and after the
// next handler.
func makeMiddleware(name string, log *bytes.Buffer) Middleware {
	return func(next RequestHandler) RequestHandler {
		return RequestHandlerFunc(func(resp Response, req Request) {
			log.WriteString(">" + name + " ")
			next.Handle(resp, req)
			log.WriteString("<" + name + " ")
		})
	}
}

func TestChainAppliesMiddlewareInOrder(t *testing.T) {
	var log bytes.Buffer
	terminal := recordingHandler{name: "H", log: &log}
	h := Chain(terminal, makeMiddleware("A", &log), makeMiddleware("B", &log), makeMiddleware("C", &log))

	req := Request{Header: packet.Header{Type: types.PacketAuthentication}}
	h.Handle(nil, req)

	// Expected: >A >B >C H|<C <B <A
	got := log.String()
	want := ">A >B >C H|<C <B <A "
	if got != want {
		t.Errorf("chain order = %q, want %q", got, want)
	}
}

// fakeResponse is a Response implementation for middleware tests that avoids
// needing a real transport.Conn.
type fakeResponse struct {
	header     packet.Header
	terminated bool
	err        error
	replied    bool
}

func (f *fakeResponse) Reply(packet.Body) error { f.replied = true; return nil }
func (f *fakeResponse) ReplyError() error       { f.replied = true; return nil }
func (f *fakeResponse) Header() packet.Header   { return f.header }
func (f *fakeResponse) Conn() *transport.Conn   { return nil }
func (f *fakeResponse) Terminate(err error)     { f.terminated = true; f.err = err }
func (f *fakeResponse) Terminated() bool        { return f.terminated }
func (f *fakeResponse) Err() error              { return f.err }

// panickingHandler always panics, to exercise RecoveryMiddleware.
type panickingHandler struct{ msg string }

func (p panickingHandler) Handle(resp Response, req Request) {
	panic(p.msg)
}

func TestRecoveryMiddlewareCatchesPanic(t *testing.T) {
	var log bytes.Buffer
	logger := newCaptureLogger(&log)

	h := Chain(panickingHandler{msg: "boom"}, RecoveryMiddleware(logger))

	resp := &fakeResponse{}
	req := Request{Header: packet.Header{Type: types.PacketAuthentication}}
	h.Handle(resp, req)

	if !resp.Terminated() {
		t.Fatal("expected response terminated after panic")
	}
	if !strings.Contains(resp.Err().Error(), "boom") {
		t.Errorf("err = %q, want it to contain 'boom'", resp.Err())
	}
	if !strings.Contains(log.String(), "panic") {
		t.Errorf("expected panic logged, got %q", log.String())
	}
}

// countingMetrics counts IncPacketReceived calls by packet type.
type countingMetrics struct {
	counts map[types.PacketType]int
}

func newCountingMetrics() *countingMetrics {
	return &countingMetrics{counts: make(map[types.PacketType]int)}
}

func (c *countingMetrics) IncPacketReceived(pt types.PacketType) { c.counts[pt]++ }
func (c *countingMetrics) IncPacketInvalid(string)               {}
func (c *countingMetrics) IncAuthenStatus(types.AuthenStatus)    {}
func (c *countingMetrics) IncAuthorStatus(types.AuthorStatus)    {}
func (c *countingMetrics) IncAcctStatus(types.AcctStatus)        {}
func (c *countingMetrics) IncSecretLookup(bool)                  {}
func (c *countingMetrics) ObserveSessionDuration(time.Duration)  {}
func (c *countingMetrics) IncSessionActive()                     {}
func (c *countingMetrics) DecSessionActive()                     {}

func TestMetricsMiddlewareCountsReceived(t *testing.T) {
	m := newCountingMetrics()
	terminal := RequestHandlerFunc(func(resp Response, req Request) {})
	h := Chain(terminal, MetricsMiddleware(m))

	req := Request{Header: packet.Header{Type: types.PacketAccounting}}
	h.Handle(&fakeResponse{}, req)
	h.Handle(&fakeResponse{}, req)

	if m.counts[types.PacketAccounting] != 2 {
		t.Errorf("counts[Accounting] = %d, want 2", m.counts[types.PacketAccounting])
	}
}

// captureLogger is a minimal types.Logger that appends formatted messages to
// a buffer. It is used to test logging middleware.
type captureLogger struct {
	buf *bytes.Buffer
}

func newCaptureLogger(b *bytes.Buffer) *captureLogger { return &captureLogger{buf: b} }

func (c *captureLogger) Enabled(context.Context, slog.Level) bool { return true }
func (c *captureLogger) Debug(msg string, args ...any)            { c.write(msg, args) }
func (c *captureLogger) Info(msg string, args ...any)             { c.write(msg, args) }
func (c *captureLogger) Warn(msg string, args ...any)             { c.write(msg, args) }
func (c *captureLogger) Error(msg string, args ...any)            { c.write(msg, args) }
func (c *captureLogger) Log(_ context.Context, _ slog.Level, msg string, args ...any) {
	c.write(msg, args)
}
func (c *captureLogger) With(args ...any) types.Logger { return c }
func (c *captureLogger) WithGroup(string) types.Logger { return c }

func (c *captureLogger) write(msg string, args []any) {
	c.buf.WriteString(msg)
	for i := 0; i+1 < len(args); i += 2 {
		c.buf.WriteString(" ")
		c.buf.WriteString(fmt.Sprint(args[i]))
		c.buf.WriteString("=")
		c.buf.WriteString(fmt.Sprint(args[i+1]))
	}
	c.buf.WriteString("\n")
}
