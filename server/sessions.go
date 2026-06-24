// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package server

import (
	"context"
	"sync"
	"time"

	"github.com/wxccs/tacacs/errors"
	"github.com/wxccs/tacacs/types"
)

// defaultSessionTTL is the idle TTL applied to a session when none is
// configured. RFC 8907 does not mandate a value; 5 minutes balances nat
// timeouts against resource cleanup.
const defaultSessionTTL = 5 * time.Minute

// defaultSweepInterval is how often SweepLoop scans for expired sessions.
const defaultSweepInterval = time.Minute

// sessionContext tracks the per-session state of an interactive
// authentication: the START context (so a CONTINUE can be matched to its
// START), the flags observed on the first packet (so single-connect
// multiplexed sessions enforce flag consistency), and bookkeeping for TTL
// expiry.
type sessionContext struct {
	// start is the authentication START captured on seq_no=1, replayed to
	// the Handler for subsequent CONTINUE packets.
	start AuthenStart
	// flags is the header flags observed on the first packet of the session.
	// Subsequent packets on the same session (under single-connect) MUST
	// carry the same flags (RFC 8907 §4.3).
	flags types.HeaderFlags
	// remoteAddr is the best-effort client address (may be PROXY-resolved).
	remoteAddr string
	// createdAt is when the START was received.
	createdAt time.Time
	// lastActive is updated on every packet in this session, used for TTL.
	lastActive time.Time
	// lastOutboundSeq is the last seq_no the server sent on this session.
	// The next inbound client packet MUST be lastOutboundSeq+1 (RFC §11).
	lastOutboundSeq byte
}

// sessionManager is a concurrency-safe registry of active TACACS+ sessions.
// It replaces the naive map[uint32]AuthenStart previously embedded in Server,
// which was a data race under per-connection goroutines.
//
// The manager supports single-connection multiplexing: multiple sessions may
// be in flight on the same transport.Conn, keyed by SessionID. A background
// sweep goroutine evicts idle sessions past their TTL.
type sessionManager struct {
	mu       sync.RWMutex
	sessions map[uint32]*sessionContext
	ttl      time.Duration
	metrics  Metrics
}

// newSessionManager creates a sessionManager with the given idle TTL and
// metrics hook. A ttl <= 0 falls back to defaultSessionTTL. A nil metrics
// falls back to NopMetrics.
func newSessionManager(ttl time.Duration, m Metrics) *sessionManager {
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	if m == nil {
		m = NopMetrics()
	}
	return &sessionManager{
		sessions: make(map[uint32]*sessionContext),
		ttl:      ttl,
		metrics:  m,
	}
}

// Get returns the sessionContext for the given id, or nil/false if absent.
func (sm *sessionManager) Get(id uint32) (*sessionContext, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	ctx, ok := sm.sessions[id]
	return ctx, ok
}

// Set registers a new session and bumps the active-session gauge. If a
// session with the same id already exists it is replaced.
func (sm *sessionManager) Set(id uint32, ctx *sessionContext) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	now := time.Now()
	ctx.createdAt = now
	ctx.lastActive = now
	_, existed := sm.sessions[id]
	sm.sessions[id] = ctx
	if !existed {
		sm.metrics.IncSessionActive()
	}
}

// Update applies fn to the session identified by id and refreshes lastActive.
// If the session is absent or fn is nil, Update is a no-op.
func (sm *sessionManager) Update(id uint32, fn func(*sessionContext)) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	ctx, ok := sm.sessions[id]
	if !ok {
		return
	}
	ctx.lastActive = time.Now()
	if fn != nil {
		fn(ctx)
	}
}

// Delete removes a session and decrements the active gauge. Removing a
// non-existent session is a no-op.
func (sm *sessionManager) Delete(id uint32) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if _, ok := sm.sessions[id]; ok {
		delete(sm.sessions, id)
		sm.metrics.DecSessionActive()
	}
}

// SweepExpired removes sessions whose lastActive exceeds the TTL and records
// their observed duration. It is intended to be called periodically by
// SweepLoop, but may also be invoked directly in tests.
func (sm *sessionManager) SweepExpired() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	now := time.Now()
	for id, ctx := range sm.sessions {
		if now.Sub(ctx.lastActive) > sm.ttl {
			delete(sm.sessions, id)
			sm.metrics.DecSessionActive()
			sm.metrics.ObserveSessionDuration(now.Sub(ctx.createdAt))
		}
	}
}

// SweepLoop runs SweepExpired on a ticker until ctx is cancelled. It is
// intended to be run as a background goroutine:
//
//	go sm.SweepLoop(ctx, 0)
//
// An interval <= 0 falls back to defaultSweepInterval.
func (sm *sessionManager) SweepLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = defaultSweepInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sm.SweepExpired()
		}
	}
}

// ValidateNextSeqNo enforces strict monotonically increasing sequence numbers
// within a session. The client must send lastOutboundSeq+1 next; any other
// value is a protocol violation (RFC 8907 §11: the sequence number must never
// wrap and must increase by 1 per hop).
//
// inbound is the client's seq_no on the current packet. lastOutboundSeq is
// the last seq_no the server sent (0 means no prior server packet, i.e. the
// inbound packet must be the START with seq_no=1).
func ValidateNextSeqNo(inbound, lastOutboundSeq byte) error {
	expected := lastOutboundSeq + 1
	if lastOutboundSeq == 0 {
		expected = 1 // first packet of a session
	}
	if inbound != expected {
		return errors.NewValidationError(
			"seq_no",
			"unexpected sequence number",
			errors.ErrInvalidSeqNo,
		)
	}
	return nil
}
