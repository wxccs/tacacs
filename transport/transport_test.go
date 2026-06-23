// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tacerrs "github.com/wxccs/tacacs/errors"
	"github.com/wxccs/tacacs/packet"
	"github.com/wxccs/tacacs/types"
)

func TestFramingRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	hdr := packet.Header{
		Version: types.VersionDefault, Type: types.PacketAuthentication, SeqNo: 1,
		SessionID: 0xdeadbeef,
	}
	body := []byte("the quick brown fox")
	require.NoError(t, WritePacket(&buf, hdr, body))

	gotHdr, gotBody, err := ReadPacket(&buf)
	require.NoError(t, err)
	assert.Equal(t, uint32(len(body)), gotHdr.Length)
	assert.Equal(t, body, gotBody)
}

func TestReadPacketShortHeader(t *testing.T) {
	_, _, err := ReadPacket(bytes.NewReader([]byte{1, 2, 3}))
	assert.Error(t, err)
}

func TestReadPacketShortBody(t *testing.T) {
	var buf bytes.Buffer
	hdr := packet.Header{Version: types.VersionDefault, Type: types.PacketAuthentication, SeqNo: 1, Length: 10}
	hb, _ := hdr.MarshalBinary()
	buf.Write(hb)
	buf.Write([]byte("only5")) // too short
	_, _, err := ReadPacket(&buf)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestConnLegacyObfuscationRoundtrip(t *testing.T) {
	// In-memory pipe: write on a, read on b.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	secret := []byte("sharedsecret")
	ca := NewConn(a, ModeLegacy, secret)
	cb := NewConn(b, ModeLegacy, secret)

	hdr := packet.Header{
		Version: types.VersionDefault, Type: types.PacketAuthentication, SeqNo: 1,
		SessionID: 0x12345678,
	}
	body := []byte("obfuscation roundtrip body")

	done := make(chan error, 1)
	go func() {
		done <- ca.WritePacket(hdr, body)
	}()

	gotHdr, gotBody, err := cb.ReadPacket()
	require.NoError(t, err)
	require.NoError(t, <-done)
	assert.Equal(t, body, gotBody, "body must de-obfuscate to original")
	assert.Equal(t, hdr.SessionID, gotHdr.SessionID)
	assert.Equal(t, uint32(len(body)), gotHdr.Length)
}

func TestConnTLSNoObfuscation(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ca := NewConn(a, ModeTLS, nil)
	cb := NewConn(b, ModeTLS, nil)

	hdr := packet.Header{
		Version: types.VersionDefault, Type: types.PacketAuthentication, SeqNo: 1,
		SessionID: 0xabcdef00,
	}
	body := []byte("cleartext under TLS")

	done := make(chan error, 1)
	go func() { done <- ca.WritePacket(hdr, body) }()

	gotHdr, gotBody, err := cb.ReadPacket()
	require.NoError(t, err)
	require.NoError(t, <-done)
	assert.Equal(t, body, gotBody)
	assert.True(t, gotHdr.Flags.Has(types.FlagUnencrypted), "TLS must set unencrypted flag")
}

func TestTCPLoopbackLegacyRoundtrip(t *testing.T) {
	port := freePort(t)
	ln, err := Listen("tcp", "127.0.0.1:"+itoa(port))
	require.NoError(t, err)
	defer ln.Close()

	secret := []byte("key123")
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		conn := Accept(c, ModeLegacy, secret)
		hdr, body, err := conn.ReadPacket()
		if err != nil {
			return
		}
		// Echo back with seq_no+1.
		hdr.SeqNo++
		_ = conn.WritePacket(hdr, body)
	}()

	ctx := context.Background()
	c, err := Dial(ctx, "tcp", "127.0.0.1:"+itoa(port), secret)
	require.NoError(t, err)
	defer c.Close()

	hdr := packet.Header{
		Version: types.VersionDefault, Type: types.PacketAuthentication, SeqNo: 1,
		SessionID: 0x0badf00d,
	}
	body := []byte("tcp loopback obfuscated payload")
	require.NoError(t, c.WritePacket(hdr, body))

	gotHdr, gotBody, err := c.ReadPacket()
	require.NoError(t, err)
	assert.Equal(t, body, gotBody)
	assert.Equal(t, byte(2), gotHdr.SeqNo)
}

func TestTLSLoopbackRoundtrip(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	serverCert := ca.leaf(t, "localhost")
	clientCert := ca.leaf(t, "client")

	serverCfg := ServerTLSConfig(serverCert, ca.pool())
	port := freePort(t)
	ln, err := ListenTLS("tcp", "127.0.0.1:"+itoa(port), serverCfg)
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		conn := Accept(c, ModeTLS, nil)
		hdr, body, err := conn.ReadPacket()
		if err != nil {
			return
		}
		hdr.SeqNo++
		_ = conn.WritePacket(hdr, body)
	}()

	clientCfg := TLSConfig{
		ServerName: "localhost",
		CACertPool: ca.pool(),
		ClientCert: clientCert,
	}
	tlsCfg, err := clientCfg.ClientTLSConfig()
	require.NoError(t, err)

	ctx := context.Background()
	c, err := DialTLS(ctx, "tcp", "127.0.0.1:"+itoa(port), tlsCfg)
	require.NoError(t, err)
	defer c.Close()

	// Verify the negotiated protocol is TLS 1.3.
	st := c.raw.(*tls.Conn).ConnectionState()
	assert.Equal(t, uint16(tls.VersionTLS13), st.Version)

	hdr := packet.Header{
		Version: types.VersionDefault, Type: types.PacketAuthentication, SeqNo: 1,
		SessionID: 0x11111111,
	}
	body := []byte("tls 1.3 protected payload")
	require.NoError(t, c.WritePacket(hdr, body))

	gotHdr, gotBody, err := c.ReadPacket()
	require.NoError(t, err)
	assert.Equal(t, body, gotBody)
	assert.True(t, gotHdr.Flags.Has(types.FlagUnencrypted))
}

func TestEnforceTLSFlagPolicy(t *testing.T) {
	assert.NoError(t, EnforceTLSFlagPolicy(true))
	err := EnforceTLSFlagPolicy(false)
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrFlagMismatch))
}

func TestClientTLSConfigRequiresServerName(t *testing.T) {
	_, err := TLSConfig{}.ClientTLSConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ServerName")
}

func TestClientTLSConfigTLS13Only(t *testing.T) {
	cfg, err := TLSConfig{ServerName: "localhost"}.ClientTLSConfig()
	require.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MaxVersion)
}

func TestServerTLSConfigTLS13Only(t *testing.T) {
	ca := newTestCA(t, "ca")
	leaf := ca.leaf(t, "s")
	cfg := ServerTLSConfig(leaf, ca.pool())
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
}

// itoa avoids strconv to keep the test file dependency-free.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
