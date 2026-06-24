// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package server

import (
	"time"

	"github.com/wxccs/tacacs/types"
)

// Metrics is the observability interface used by the Server and sessionManager.
// The default NopMetrics discards all calls; production implementations (e.g.
// Prometheus) live in subpackages of the CLI and inject through Config.Metrics.
type Metrics interface {
	// IncPacketReceived counts an inbound packet by type.
	IncPacketReceived(pt types.PacketType)
	// IncPacketInvalid counts a packet that failed decode or flag policy.
	IncPacketInvalid(reason string)
	// IncAuthenStatus counts an authentication reply status.
	IncAuthenStatus(s types.AuthenStatus)
	// IncAuthorStatus counts an authorization reply status.
	IncAuthorStatus(s types.AuthorStatus)
	// IncAcctStatus counts an accounting reply status.
	IncAcctStatus(s types.AcctStatus)
	// IncSecretLookup counts SecretProvider lookups, hit=true on match.
	IncSecretLookup(hit bool)
	// ObserveSessionDuration records the wall-clock duration of a session.
	ObserveSessionDuration(d time.Duration)
	// IncSessionActive / DecSessionActive track the active session gauge.
	IncSessionActive()
	DecSessionActive()
}

// nopMetrics implements Metrics with no-op methods.
type nopMetrics struct{}

// NopMetrics returns a Metrics that discards all observations. It is the
// default when Config.Metrics is nil.
func NopMetrics() Metrics { return nopMetrics{} }

func (nopMetrics) IncPacketReceived(types.PacketType)   {}
func (nopMetrics) IncPacketInvalid(string)              {}
func (nopMetrics) IncAuthenStatus(types.AuthenStatus)   {}
func (nopMetrics) IncAuthorStatus(types.AuthorStatus)   {}
func (nopMetrics) IncAcctStatus(types.AcctStatus)       {}
func (nopMetrics) IncSecretLookup(bool)                 {}
func (nopMetrics) ObserveSessionDuration(time.Duration) {}
func (nopMetrics) IncSessionActive()                    {}
func (nopMetrics) DecSessionActive()                    {}
