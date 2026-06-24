// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/transport"
	"github.com/wxccs/tacacs/types"
)

func TestParseAuthenType(t *testing.T) {
	cases := []struct {
		in   string
		want types.AuthenType
	}{
		{"ascii", types.AuthenTypeASCII},
		{"pap", types.AuthenTypePAP},
		{"chap", types.AuthenTypeCHAP},
		{"mschap", types.AuthenTypeMSCHAP},
		{"mschapv2", types.AuthenTypeMSCHAPv2},
	}
	for _, c := range cases {
		got, err := parseAuthenType(c.in)
		require.NoError(t, err)
		assert.Equal(t, c.want, got)
	}
	_, err := parseAuthenType("bogus")
	assert.Error(t, err)
}

func TestParseAcctFlags(t *testing.T) {
	assert.Equal(t, types.AcctFlagStart, mustAcctFlags("start"))
	assert.Equal(t, types.AcctFlagStop, mustAcctFlags("stop"))
	assert.Equal(t, types.AcctFlagWatchdog, mustAcctFlags("watchdog"))
	_, err := parseAcctFlags("bogus")
	assert.Error(t, err)
}

func mustAcctFlags(s string) types.AcctFlags {
	f, err := parseAcctFlags(s)
	if err != nil {
		panic(err)
	}
	return f
}

func TestRandomTaskID(t *testing.T) {
	a := randomTaskID()
	b := randomTaskID()
	assert.Len(t, a, 16) // 8 bytes hex
	assert.NotEqual(t, a, b)
}

func TestPrintResultText(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	outputFmt = "text"
	require.NoError(t, printResult(map[string]any{"status": "pass"}, true))
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()
	assert.Contains(t, out, "status: pass")
}

func TestPrintResultJSON(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	outputFmt = "json"
	require.NoError(t, printResult(map[string]any{"status": "pass", "code": 1}, true))
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, "pass", got["status"])
}

func TestServerNameFallback(t *testing.T) {
	sni = ""
	serverAddr = "10.0.0.1"
	assert.Equal(t, "10.0.0.1", serverName())
	sni = "tacacs.example.com"
	assert.Equal(t, "tacacs.example.com", serverName())
	sni = ""
}

// TestCLISmoke runs the built client binary against an in-process server,
// exercising the auth/authz/acct client commands. It is skipped unless
// TACACS_CLI_BIN points at a built binary.
func TestCLISmoke(t *testing.T) {
	bin := os.Getenv("TACACS_CLI_BIN")
	if bin == "" {
		t.Skip("set TACACS_CLI_BIN to run the CLI smoke test")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := itoaSmoke(ln.Addr().(*net.TCPAddr).Port)
	secret := "testkey"

	srv := server.New(server.Config{
		Handler: &staticHandler{users: map[string]string{"admin": "admin123"}},
		Secret:  []byte(secret), Mode: transport.ModeLegacy,
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conn := transport.Accept(c, transport.ModeLegacy, []byte(secret))
			go func() { _ = srv.ServeConn(context.Background(), conn) }()
		}
	}()
	t.Cleanup(func() { ln.Close() })

	// auth (PAP correct)
	out := runCLI(t, bin, "auth", "--server", "127.0.0.1", "--port", port, "--secret", secret,
		"--username", "admin", "--password", "admin123", "--type", "pap", "--output", "json")
	assert.Equal(t, "pass", out["status"])

	// authz (show allowed)
	out = runCLI(t, bin, "authz", "--server", "127.0.0.1", "--port", port, "--secret", secret,
		"--username", "admin", "--service", "shell", "--cmd", "show version", "--output", "json")
	assert.Equal(t, "pass-add", out["status"])

	// acct (start)
	out = runCLI(t, bin, "acct", "--server", "127.0.0.1", "--port", port, "--secret", secret,
		"--username", "admin", "--action", "start", "--output", "json")
	assert.Equal(t, "success", out["status"])
}

func runCLI(t *testing.T, bin string, args ...string) map[string]any {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	require.NoError(t, cmd.Run(), "command: %s %s\nstdout: %s\nstderr: %s", bin, strings.Join(args, " "), out.String(), errOut.String())
	var m map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &m), "stdout: %s\nstderr: %s", out.String(), errOut.String())
	return m
}

func itoaSmoke(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// keep context imported for the package (used by dial/server in non-test files).
var _ = context.Background
