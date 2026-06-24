// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package prom

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wxccs/tacacs/types"
)

// TestMetricsEmit verifies New registers all collectors without panicking and
// that exercising every method produces the expected series on /metrics,
// including the new auth-type label, AAA latency histogram and connection
// counters.
func TestMetricsEmit(t *testing.T) {
	m := New()

	m.IncPacketReceived(types.PacketAuthentication)
	m.IncPacketInvalid("flag_mismatch")
	m.IncAuthenStatus(types.AuthenTypePAP, types.AuthenStatusPass)
	m.IncAuthorStatus(types.AuthorStatusPassAdd)
	m.IncAcctStatus(types.AcctStatusSuccess)
	m.ObserveAuthenLatency(5 * time.Millisecond)
	m.ObserveAuthorLatency(time.Millisecond)
	m.ObserveAcctLatency(time.Millisecond)
	m.IncSecretLookup(true)
	m.IncConnAccepted()
	m.IncConnRejected("max_conns")
	m.IncAcceptError()
	m.ObserveSessionDuration(time.Second)
	m.IncSessionActive()
	m.DecSessionActive()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	Handler().ServeHTTP(rec, req)
	body := rec.Body.String()

	for _, want := range []string{
		`tacacs_authen_status_total{authen_type="pap",status="pass"} 1`,
		`tacacs_aaa_handler_latency_seconds_count{phase="authen"} 1`,
		`tacacs_aaa_handler_latency_seconds_count{phase="author"} 1`,
		`tacacs_aaa_handler_latency_seconds_count{phase="acct"} 1`,
		`tacacs_connections_accepted_total 1`,
		`tacacs_connections_rejected_total{reason="max_conns"} 1`,
		`tacacs_accept_errors_total 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}
