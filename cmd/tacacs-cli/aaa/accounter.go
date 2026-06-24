// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package aaa

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/types"
)

// sensitiveArgPrefixes lists AVP name prefixes whose values MUST NOT be
// persisted in accounting logs in cleartext. The value is replaced with
// "REDACTED" before serialization. This is a defense-in-depth measure:
// callers SHOULD NOT be sending such AVPs in accounting records anyway.
var sensitiveArgPrefixes = []string{
	"password",
	"secret",
	"token",
}

// AcctRecord is the on-disk JSON shape of an accounting record. The schema is
// intentionally flat to keep file consumers (jq, grep, log shippers) simple.
type AcctRecord struct {
	Timestamp string           `json:"ts"`
	SessionID uint32           `json:"session_id"`
	SeqNo     byte             `json:"seq_no"`
	Record    string           `json:"record"`
	User      string           `json:"user,omitempty"`
	Port      string           `json:"port,omitempty"`
	RemAddr   string           `json:"rem_addr,omitempty"`
	Remote    string           `json:"remote,omitempty"`
	Args      []types.Argument `json:"args,omitempty"`
}

// fromContext builds an AcctRecord from the inbound AcctContext, masking
// sensitive AVPs.
func fromContext(ac server.AcctContext) AcctRecord {
	args := make([]types.Argument, 0, len(ac.Args))
	for _, a := range ac.Args {
		if isSensitive(a.Name) {
			a.Value = "REDACTED"
		}
		args = append(args, a)
	}
	return AcctRecord{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: ac.SessionID,
		SeqNo:     ac.SeqNo,
		Record:    classify(ac.Flags),
		User:      ac.User,
		Port:      ac.Port,
		RemAddr:   ac.RemAddr,
		Remote:    ac.RemoteAddr,
		Args:      args,
	}
}

// classify maps the inbound flags byte to a human-readable record name. It
// mirrors types.AcctFlags.Record but returns the string form directly.
func classify(f types.AcctFlags) string {
	switch f.Record() {
	case types.AcctRecordStart:
		return "start"
	case types.AcctRecordStop:
		return "stop"
	case types.AcctRecordWatchdogNoUpdate:
		return "watchdog"
	case types.AcctRecordWatchdogWithUpdate:
		return "watchdog-update"
	default:
		return "invalid"
	}
}

// isSensitive reports whether the AVP name (case-insensitive) begins with any
// of the sensitive prefixes.
func isSensitive(name string) bool {
	low := strings.ToLower(name)
	for _, p := range sensitiveArgPrefixes {
		if strings.HasPrefix(low, p) {
			return true
		}
	}
	return false
}

// FileAccounter appends accounting records as JSONL to a file. The file is
// created with mode 0600; subsequent appends are serialized by a mutex so
// concurrent Account calls do not interleave lines.
type FileAccounter struct {
	mu  sync.Mutex
	f   *os.File
	enc *json.Encoder
}

// NewFileAccounter opens (or creates) path for appending. The file is created
// with mode 0600 if it does not exist; an existing file is opened O_APPEND so
// records from prior runs are preserved.
func NewFileAccounter(path string) (*FileAccounter, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open accounting log: %w", err)
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	return &FileAccounter{f: f, enc: enc}, nil
}

// Account encodes the record to the file. A write error does NOT propagate to
// the protocol reply: the caller still sees AcctStatusSuccess to avoid
// signaling accounting failure to the NAS unless the request itself was bad.
// The error is returned for the server's logging middleware to surface.
func (a *FileAccounter) Account(ctx context.Context, ac server.AcctContext) (server.AcctDecision, error) {
	rec := fromContext(ac)
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.enc.Encode(rec); err != nil {
		return server.AcctDecision{Status: types.AcctStatusSuccess}, err
	}
	return server.AcctDecision{Status: types.AcctStatusSuccess}, nil
}

// Close flushes and closes the underlying file. After Close the Accounter is
// no longer usable.
func (a *FileAccounter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return nil
	}
	err := a.f.Close()
	a.f = nil
	return err
}

// SyslogAccounter writes accounting records to syslog via the local syslog
// daemon. Each record is a single JSON line at LOG_INFO | LOG_AUTH. The
// writer is opened at construction time and closed via Close.
type SyslogAccounter struct {
	mu sync.Mutex
	w  *syslog.Writer
}

// NewSyslogAccounter dials the local syslog daemon. The facility is LOG_AUTH;
// records are written at LOG_INFO. Network/address arguments are passed
// through to syslog.Dial; pass ("", "") for the default local socket.
func NewSyslogAccounter(network, address string) (*SyslogAccounter, error) {
	w, err := syslog.Dial(network, address, syslog.LOG_INFO|syslog.LOG_AUTH, "tacacs-accounting")
	if err != nil {
		return nil, fmt.Errorf("dial syslog: %w", err)
	}
	return &SyslogAccounter{w: w}, nil
}

// Account encodes the record as JSON and writes it as a single syslog line.
// As with FileAccounter, write errors do not propagate to the protocol reply.
func (a *SyslogAccounter) Account(ctx context.Context, ac server.AcctContext) (server.AcctDecision, error) {
	rec := fromContext(ac)
	buf, err := json.Marshal(rec)
	if err != nil {
		return server.AcctDecision{Status: types.AcctStatusSuccess}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.w.Info(string(buf)); err != nil {
		return server.AcctDecision{Status: types.AcctStatusSuccess}, err
	}
	return server.AcctDecision{Status: types.AcctStatusSuccess}, nil
}

// Close releases the syslog writer.
func (a *SyslogAccounter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.w == nil {
		return nil
	}
	err := a.w.Close()
	a.w = nil
	return err
}

// Compile-time assertions that FileAccounter and SyslogAccounter satisfy the
// Accounter interface expected by CompositeHandler.
var (
	_ Accounter = (*FileAccounter)(nil)
	_ Accounter = (*SyslogAccounter)(nil)
	_ io.Closer = (*FileAccounter)(nil)
	_ io.Closer = (*SyslogAccounter)(nil)
)
