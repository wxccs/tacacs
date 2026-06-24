// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package interop_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tq "github.com/facebookincubator/tacquito"

	"github.com/wxccs/tacacs/client"
	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/transport"
	"github.com/wxccs/tacacs/types"
)

// testSecret is the shared key used for both directions of interop. It is a
// public test fixture, never a production secret.
const testSecret = "interop-testkey"

// testUser / testPassword are the credentials accepted by the PAP/ASCII
// handlers in both directions.
const (
	testUser     = "alice"
	testPassword = "hunter2"
)

// stubLogger implements tacquito.loggerProvider by forwarding to testing.T
// via Logf. It is intentionally verbose-free by default; tests can flip the
// debug flag to inspect packets.
type stubLogger struct {
	t     *testing.T
	debug bool
}

func (l stubLogger) Infof(ctx context.Context, format string, args ...any) {
	l.t.Logf("[tacquito INFO] "+format, args...)
}
func (l stubLogger) Errorf(ctx context.Context, format string, args ...any) {
	l.t.Logf("[tacquito ERROR] "+format, args...)
}
func (l stubLogger) Debugf(ctx context.Context, format string, args ...any) {
	if l.debug {
		l.t.Logf("[tacquito DEBUG] "+format, args...)
	}
}
func (l stubLogger) Record(ctx context.Context, r map[string]string, obscure ...string) {
	if l.debug {
		l.t.Logf("[tacquito RECORD] %v (obscure=%v)", r, obscure)
	}
}

// tacquitoStubHandler is a minimal tq.Handler that answers PAP and ASCII
// authentication, plus authorize/accounting, against fixed credentials.
type tacquitoStubHandler struct {
	logger stubLogger
}

func (h *tacquitoStubHandler) Handle(response tq.Response, request tq.Request) {
	switch request.Header.Type {
	case tq.Authenticate:
		h.handleAuthen(response, request)
	case tq.Authorize:
		h.handleAuthor(response, request)
	case tq.Accounting:
		h.handleAcct(response, request)
	default:
		response.Reply(tq.NewAuthenReply(
			tq.SetAuthenReplyStatus(tq.AuthenStatusError),
			tq.SetAuthenReplyServerMsg("unknown packet type"),
		))
	}
}

// handleAuthen routes PAP directly to Pass/Fail and ASCII into a CONTINUE
// loop driven by stubASCIIContinue.
func (h *tacquitoStubHandler) handleAuthen(response tq.Response, request tq.Request) {
	var start tq.AuthenStart
	if err := tq.Unmarshal(request.Body, &start); err != nil {
		// Could be a CONTINUE in the ASCII flow; route to the next handler.
		var cont tq.AuthenContinue
		if err2 := tq.Unmarshal(request.Body, &cont); err2 == nil {
			if string(cont.UserMessage) == testPassword {
				response.Reply(tq.NewAuthenReply(
					tq.SetAuthenReplyStatus(tq.AuthenStatusPass),
				))
				return
			}
			response.Reply(tq.NewAuthenReply(
				tq.SetAuthenReplyStatus(tq.AuthenStatusFail),
				tq.SetAuthenReplyServerMsg("bad password"),
			))
			return
		}
		response.Reply(tq.NewAuthenReply(
			tq.SetAuthenReplyStatus(tq.AuthenStatusError),
			tq.SetAuthenReplyServerMsg("decode error"),
		))
		return
	}

	switch start.Type {
	case tq.AuthenTypePAP:
		if string(start.User) == testUser && string(start.Data) == testPassword {
			response.Reply(tq.NewAuthenReply(
				tq.SetAuthenReplyStatus(tq.AuthenStatusPass),
			))
			return
		}
		response.Reply(tq.NewAuthenReply(
			tq.SetAuthenReplyStatus(tq.AuthenStatusFail),
			tq.SetAuthenReplyServerMsg("bad credentials"),
		))
	case tq.AuthenTypeASCII:
		// First packet: ask for password. The next CONTINUE will hit the
		// CONTINUE branch above via response.Next registration.
		response.Next(tq.HandlerFunc(func(r tq.Response, req tq.Request) {
			h.handleAuthen(r, req)
		}))
		response.Reply(tq.NewAuthenReply(
			tq.SetAuthenReplyStatus(tq.AuthenStatusGetPass),
			tq.SetAuthenReplyServerMsg("Password:"),
		))
	default:
		response.Reply(tq.NewAuthenReply(
			tq.SetAuthenReplyStatus(tq.AuthenStatusFail),
			tq.SetAuthenReplyServerMsg("unsupported authen type"),
		))
	}
}

func (h *tacquitoStubHandler) handleAuthor(response tq.Response, request tq.Request) {
	var ar tq.AuthorRequest
	if err := tq.Unmarshal(request.Body, &ar); err != nil {
		response.Reply(tq.NewAuthorReply(tq.SetAuthorReplyStatus(tq.AuthorStatusFail)))
		return
	}
	// Permit any "cmd=show ..." AVP; deny everything else.
	for _, a := range ar.Args {
		if strings.HasPrefix(string(a), "cmd=show") {
			response.Reply(tq.NewAuthorReply(
				tq.SetAuthorReplyStatus(tq.AuthorStatusPassAdd),
			))
			return
		}
	}
	response.Reply(tq.NewAuthorReply(tq.SetAuthorReplyStatus(tq.AuthorStatusFail)))
}

func (h *tacquitoStubHandler) handleAcct(response tq.Response, request tq.Request) {
	var ar tq.AcctRequest
	if err := tq.Unmarshal(request.Body, &ar); err != nil {
		response.Reply(tq.NewAcctReply(tq.SetAcctReplyStatus(tq.AcctReplyStatusError)))
		return
	}
	response.Reply(tq.NewAcctReply(tq.SetAcctReplyStatus(tq.AcctReplyStatusSuccess)))
}

// tacquitoStubSecret returns a fixed secret + handler for any peer.
type tacquitoStubSecret struct {
	handler tq.Handler
}

func (s *tacquitoStubSecret) Get(ctx context.Context, remote net.Addr) ([]byte, tq.Handler, error) {
	return []byte(testSecret), s.handler, nil
}

// startTacquitoServer brings up a tacquito server bound to a random local port.
// It returns the listener (for address lookup) and a cancel function.
func startTacquitoServer(t *testing.T, debug bool) (string, context.CancelFunc) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	logger := stubLogger{t: t, debug: debug}
	handler := &tacquitoStubHandler{logger: logger}
	sp := &tacquitoStubSecret{handler: handler}
	srv := tq.NewServer(logger, sp)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = srv.Serve(ctx, ln.(tq.DeadlineListener))
	}()
	return ln.Addr().String(), cancel
}

// startLocalServer brings up a local server with the memHandler used in
// client/e2e_test.go-style tests. Returns the listen address and a cancel.
func startLocalServer(t *testing.T) (string, context.CancelFunc) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	secret := []byte(testSecret)
	srv := server.New(server.Config{
		Handler: &interopHandler{},
		Secret:  secret,
		Mode:    transport.ModeLegacy,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
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
	return ln.Addr().String(), cancel
}

// interopHandler is the local-side memHandler with fixed credentials and
// command/authorize/accounting responses matching the tacquito stub above.
type interopHandler struct{}

func (h *interopHandler) Authenticate(ctx context.Context, ac server.AuthenContext, cont *server.AuthenContinue) (server.AuthenDecision, error) {
	if cont == nil {
		if ac.Start.Type == types.AuthenTypePAP {
			if ac.Start.User == testUser && string(ac.Start.Data) == testPassword {
				return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
			}
			return server.AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "bad credentials"}, nil
		}
		// ASCII: ask for password.
		return server.AuthenDecision{Status: types.AuthenStatusGetPass, ServerMsg: "Password:"}, nil
	}
	if cont.UserMsg == testPassword {
		return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
	}
	return server.AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "bad password"}, nil
}

func (h *interopHandler) Authorize(ctx context.Context, ac server.AuthorContext) (server.AuthorDecision, error) {
	for _, a := range ac.Args {
		if a.Name == "cmd" && strings.HasPrefix(a.Value, "show") {
			return server.AuthorDecision{Status: types.AuthorStatusPassAdd}, nil
		}
	}
	return server.AuthorDecision{Status: types.AuthorStatusFail}, nil
}

func (h *interopHandler) Account(ctx context.Context, ac server.AcctContext) (server.AcctDecision, error) {
	return server.AcctDecision{Status: types.AcctStatusSuccess}, nil
}

// ---------------------------------------------------------------------------
// Direction 1: local client → tacquito server
// ---------------------------------------------------------------------------

func TestLocalClientToTacquitoServer_PAP(t *testing.T) {
	addr, cancel := startTacquitoServer(t, false)
	defer cancel()

	conn, err := transport.Dial(context.Background(), "tcp", addr, []byte(testSecret))
	require.NoError(t, err)
	defer conn.Close()

	c, err := client.New(conn)
	require.NoError(t, err)

	ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	reply, err := c.Authenticate(ctx, client.AuthenRequest{
		Action:  types.AuthenLogin,
		PrivLvl: 0,
		Type:    types.AuthenTypePAP,
		Service: types.AuthenServiceLogin,
		User:    testUser,
		Port:    "tty0",
		RemAddr: "127.0.0.1",
		Data:    []byte(testPassword),
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, types.AuthenStatusPass, reply.Status, "PAP should pass against tacquito server")
}

func TestLocalClientToTacquitoServer_ASCII(t *testing.T) {
	addr, cancel := startTacquitoServer(t, false)
	defer cancel()

	conn, err := transport.Dial(context.Background(), "tcp", addr, []byte(testSecret))
	require.NoError(t, err)
	defer conn.Close()

	c, err := client.New(conn)
	require.NoError(t, err)

	ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	reply, err := c.Authenticate(ctx, client.AuthenRequest{
		Action:  types.AuthenLogin,
		PrivLvl: 0,
		Type:    types.AuthenTypeASCII,
		Service: types.AuthenServiceLogin,
		User:    testUser,
		Port:    "tty0",
		RemAddr: "127.0.0.1",
	}, func(r client.AuthenReply) (string, error) {
		if r.Status != types.AuthenStatusGetPass {
			return "", fmt.Errorf("expected GetPass, got %d", r.Status)
		}
		return testPassword, nil
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthenStatusPass, reply.Status, "ASCII should pass against tacquito server")
}

func TestLocalClientToTacquitoServer_Authorize(t *testing.T) {
	addr, cancel := startTacquitoServer(t, false)
	defer cancel()

	conn, err := transport.Dial(context.Background(), "tcp", addr, []byte(testSecret))
	require.NoError(t, err)
	defer conn.Close()

	c, err := client.New(conn)
	require.NoError(t, err)

	ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	res, err := c.Authorize(ctx, client.AuthorRequest{
		Method:  types.AuthenMethodTacacsPlus,
		PrivLvl: 0,
		Type:    types.AuthenTypeNotSet,
		Service: types.AuthenServiceLogin,
		User:    testUser,
		Port:    "tty0",
		RemAddr: "127.0.0.1",
		Args:    []types.Argument{{Mandatory: true, Name: "cmd", Value: "show version"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthorStatusPassAdd, res.Status, "Authorize should PassAdd against tacquito server")
}

func TestLocalClientToTacquitoServer_Accounting(t *testing.T) {
	addr, cancel := startTacquitoServer(t, false)
	defer cancel()

	conn, err := transport.Dial(context.Background(), "tcp", addr, []byte(testSecret))
	require.NoError(t, err)
	defer conn.Close()

	c, err := client.New(conn)
	require.NoError(t, err)

	ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	res, err := c.Account(ctx, client.AcctRequest{
		Flags:   types.AcctFlagStart,
		Method:  types.AuthenMethodTacacsPlus,
		PrivLvl: 0,
		Type:    types.AuthenTypeNotSet,
		Service: types.AuthenServiceLogin,
		User:    testUser,
		Port:    "tty0",
		RemAddr: "127.0.0.1",
		Args:    []types.Argument{{Mandatory: true, Name: "task_id", Value: "1"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AcctStatusSuccess, res.Status, "Accounting should succeed against tacquito server")
}

// ---------------------------------------------------------------------------
// Direction 2: tacquito client → local server
// ---------------------------------------------------------------------------

// tacquitoSend opens a tacquito client, sends one packet, and returns the
// response packet. Fails the test if Send errors.
func tacquitoSend(t *testing.T, addr string, packet *tq.Packet) *tq.Packet {
	t.Helper()
	c, err := tq.NewClient(tq.SetClientDialer("tcp", addr, []byte(testSecret)))
	require.NoError(t, err)
	defer c.Close()
	resp, err := c.Send(packet)
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp
}

func TestTacquitoClientToLocalServer_PAP(t *testing.T) {
	addr, cancel := startLocalServer(t)
	defer cancel()

	start := tq.NewAuthenStart(
		tq.SetAuthenStartAction(tq.AuthenActionLogin),
		tq.SetAuthenStartPrivLvl(tq.PrivLvl(0)),
		tq.SetAuthenStartType(tq.AuthenTypePAP),
		tq.SetAuthenStartService(tq.AuthenServiceLogin),
		tq.SetAuthenStartPort("tty0"),
		tq.SetAuthenStartRemAddr("127.0.0.1"),
		tq.SetAuthenStartUser(tq.AuthenUser(testUser)),
		tq.SetAuthenStartData(tq.AuthenData(testPassword)),
	)
	pkt := tq.NewPacket(
		tq.SetPacketHeader(tq.NewHeader(
			tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionOne}),
			tq.SetHeaderType(tq.Authenticate),
			tq.SetHeaderRandomSessionID(),
		)),
		tq.SetPacketBodyUnsafe(start),
	)
	resp := tacquitoSend(t, addr, pkt)

	var reply tq.AuthenReply
	require.NoError(t, tq.Unmarshal(resp.Body, &reply))
	assert.Equal(t, tq.AuthenStatusPass, reply.Status, "tacquito client PAP should pass against local server")
}

func TestTacquitoClientToLocalServer_ASCII(t *testing.T) {
	addr, cancel := startLocalServer(t)
	defer cancel()

	c, err := tq.NewClient(tq.SetClientDialer("tcp", addr, []byte(testSecret)))
	require.NoError(t, err)
	defer c.Close()

	startPkt := tq.NewPacket(
		tq.SetPacketHeader(tq.NewHeader(
			tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionDefault}),
			tq.SetHeaderType(tq.Authenticate),
			tq.SetHeaderRandomSessionID(),
		)),
		tq.SetPacketBodyUnsafe(tq.NewAuthenStart(
			tq.SetAuthenStartAction(tq.AuthenActionLogin),
			tq.SetAuthenStartPrivLvl(tq.PrivLvl(0)),
			tq.SetAuthenStartType(tq.AuthenTypeASCII),
			tq.SetAuthenStartService(tq.AuthenServiceLogin),
			tq.SetAuthenStartPort("tty0"),
			tq.SetAuthenStartRemAddr("127.0.0.1"),
			tq.SetAuthenStartUser(tq.AuthenUser(testUser)),
		)),
	)
	resp, err := c.Send(startPkt)
	require.NoError(t, err)
	var reply tq.AuthenReply
	require.NoError(t, tq.Unmarshal(resp.Body, &reply))
	require.Equal(t, tq.AuthenStatusGetPass, reply.Status, "expected GetPass after START")

	// Continue with the password. SeqNo must be 3 (server sent 2).
	contPkt := tq.NewPacket(
		tq.SetPacketHeader(tq.NewHeader(
			tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionDefault}),
			tq.SetHeaderType(tq.Authenticate),
			tq.SetHeaderSeqNo(3),
			tq.SetHeaderSessionID(startPkt.Header.SessionID),
		)),
		tq.SetPacketBodyUnsafe(tq.NewAuthenContinue(
			tq.SetAuthenContinueUserMessage(tq.AuthenUserMessage(testPassword)),
		)),
	)
	resp2, err := c.Send(contPkt)
	require.NoError(t, err)
	require.NoError(t, tq.Unmarshal(resp2.Body, &reply))
	assert.Equal(t, tq.AuthenStatusPass, reply.Status, "ASCII should pass after CONTINUE")
}

func TestTacquitoClientToLocalServer_Authorize(t *testing.T) {
	addr, cancel := startLocalServer(t)
	defer cancel()

	pkt := tq.NewPacket(
		tq.SetPacketHeader(tq.NewHeader(
			tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionOne}),
			tq.SetHeaderType(tq.Authorize),
			tq.SetHeaderRandomSessionID(),
		)),
		tq.SetPacketBodyUnsafe(tq.NewAuthorRequest(
			tq.SetAuthorRequestPrivLvl(tq.PrivLvl(0)),
			tq.SetAuthorRequestType(tq.AuthenTypeNotSet),
			tq.SetAuthorRequestService(tq.AuthenServiceLogin),
			tq.SetAuthorRequestPort("tty0"),
			tq.SetAuthorRequestRemAddr("127.0.0.1"),
			tq.SetAuthorRequestUser(testUser),
			tq.SetAuthorRequestArgs(tq.Args{tq.Arg("cmd=show version")}),
		)),
	)
	resp := tacquitoSend(t, addr, pkt)

	var reply tq.AuthorReply
	require.NoError(t, tq.Unmarshal(resp.Body, &reply))
	assert.Equal(t, tq.AuthorStatusPassAdd, reply.Status, "tacquito client authorize should PassAdd against local server")
}

func TestTacquitoClientToLocalServer_Accounting(t *testing.T) {
	addr, cancel := startLocalServer(t)
	defer cancel()

	pkt := tq.NewPacket(
		tq.SetPacketHeader(tq.NewHeader(
			tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionOne}),
			tq.SetHeaderType(tq.Accounting),
			tq.SetHeaderRandomSessionID(),
		)),
		tq.SetPacketBodyUnsafe(tq.NewAcctRequest(
			tq.SetAcctRequestFlag(tq.AcctFlagStart),
			tq.SetAcctRequestMethod(tq.AuthenMethodTacacsPlus),
			tq.SetAcctRequestPrivLvl(tq.PrivLvl(0)),
			tq.SetAcctRequestType(tq.AuthenTypeNotSet),
			tq.SetAcctRequestService(tq.AuthenServiceLogin),
			tq.SetAcctRequestPort("tty0"),
			tq.SetAcctRequestRemAddr("127.0.0.1"),
			tq.SetAcctRequestUser(testUser),
			tq.SetAcctRequestArgs(tq.Args{tq.Arg("task_id=1")}),
		)),
	)
	resp := tacquitoSend(t, addr, pkt)

	var reply tq.AcctReply
	require.NoError(t, tq.Unmarshal(resp.Body, &reply))
	assert.Equal(t, tq.AcctReplyStatusSuccess, reply.Status, "tacquito client accounting should succeed against local server")
}

// ---------------------------------------------------------------------------
// TLS interop (RFC 9887)
// ---------------------------------------------------------------------------

// interopTestCA generates a self-signed ECDSA P-256 CA and signs leaf certs.
// Mirrors the pattern in client/certest_test.go but lives in the interop
// package so we can share it across both TLS directions.
type interopTestCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certDER []byte
}

func newInteropTestCA(t *testing.T, name string) *interopTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	ca, _ := x509.ParseCertificate(der)
	return &interopTestCA{cert: ca, key: key, certDER: der}
}

func (c *interopTestCA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

func (c *interopTestCA) leaf(t *testing.T, san string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: san},
		DNSNames:     []string{san},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der, c.certDER}, PrivateKey: key}
}

// startTacquitoServerTLS brings up a tacquito server with TLS 1.3 enabled.
// The server does NOT require client certificates; the local client can
// authenticate with just a CA pool.
func startTacquitoServerTLS(t *testing.T) (string, context.CancelFunc) {
	t.Helper()
	ca := newInteropTestCA(t, "tacquito-ca")
	serverCert := ca.leaf(t, "localhost")
	serverTLS := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tcpLn := ln.(*net.TCPListener)
	tlsLn, err := tq.NewTLSListener(tcpLn, serverTLS)
	require.NoError(t, err)
	logger := stubLogger{t: t}
	handler := &tacquitoStubHandler{logger: logger}
	sp := &tacquitoStubSecret{handler: handler}
	srv := tq.NewServer(logger, sp, tq.SetUseTLS(true))
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, tlsLn) }()
	return ln.Addr().String(), cancel
}

// startLocalServerTLS brings up a local server with TLS 1.3 enabled. Uses
// transport.ServerTLSConfig which requires mutual TLS authentication, so the
// tacquito client must present a cert signed by the same CA.
func startLocalServerTLS(t *testing.T) (string, *interopTestCA, context.CancelFunc) {
	t.Helper()
	ca := newInteropTestCA(t, "local-ca")
	serverCert := ca.leaf(t, "localhost")
	srvCfg := transport.ServerTLSConfig(serverCert, ca.pool())
	ln, err := transport.ListenTLS("tcp", "127.0.0.1:0", srvCfg)
	require.NoError(t, err)
	srv := server.New(server.Config{
		Handler: &interopHandler{},
		Secret:  nil,
		Mode:    transport.ModeTLS,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conn := transport.Accept(c, transport.ModeTLS, nil)
			go func() { _ = srv.ServeConn(context.Background(), conn) }()
		}
	}()
	return ln.Addr().String(), ca, cancel
}

func TestLocalClientToTacquitoServer_TLS_PAP(t *testing.T) {
	addr, cancel := startTacquitoServerTLS(t)
	defer cancel()

	// Build a client TLS config that trusts the in-memory CA pool. We don't
	// have direct access to the tacquito server's CA, so we use InsecureSkipVerify
	// for the test fixture (acceptable: this is a localhost interop test).
	clientTLS := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}
	conn, err := transport.DialTLS(context.Background(), "tcp", addr, clientTLS)
	require.NoError(t, err)
	defer conn.Close()

	c, err := client.New(conn)
	require.NoError(t, err)

	ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	reply, err := c.Authenticate(ctx, client.AuthenRequest{
		Action:  types.AuthenLogin,
		PrivLvl: 0,
		Type:    types.AuthenTypePAP,
		Service: types.AuthenServiceLogin,
		User:    testUser,
		Port:    "tty0",
		RemAddr: "127.0.0.1",
		Data:    []byte(testPassword),
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, types.AuthenStatusPass, reply.Status, "TLS PAP should pass against tacquito server")
}

func TestTacquitoClientToLocalServer_TLS_PAP(t *testing.T) {
	addr, ca, cancel := startLocalServerTLS(t)
	defer cancel()

	// The local server requires mutual TLS; build a client cert signed by
	// the same CA so tacquito's client can present it.
	clientCert := ca.leaf(t, "client")
	clientTLS := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:            ca.pool(),
		InsecureSkipVerify: true, // skip hostname verification for localhost test
	}
	c, err := tq.NewClient(tq.SetClientTLSDialer("tcp", addr, clientTLS))
	require.NoError(t, err)
	defer c.Close()

	start := tq.NewAuthenStart(
		tq.SetAuthenStartAction(tq.AuthenActionLogin),
		tq.SetAuthenStartPrivLvl(tq.PrivLvl(0)),
		tq.SetAuthenStartType(tq.AuthenTypePAP),
		tq.SetAuthenStartService(tq.AuthenServiceLogin),
		tq.SetAuthenStartPort("tty0"),
		tq.SetAuthenStartRemAddr("127.0.0.1"),
		tq.SetAuthenStartUser(tq.AuthenUser(testUser)),
		tq.SetAuthenStartData(tq.AuthenData(testPassword)),
	)
	pkt := tq.NewPacket(
		tq.SetPacketHeader(tq.NewHeader(
			tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionOne}),
			tq.SetHeaderType(tq.Authenticate),
			tq.SetHeaderRandomSessionID(),
		)),
		tq.SetPacketBodyUnsafe(start),
	)
	resp, err := c.Send(pkt)
	require.NoError(t, err)
	var reply tq.AuthenReply
	require.NoError(t, tq.Unmarshal(resp.Body, &reply))
	assert.Equal(t, tq.AuthenStatusPass, reply.Status, "tacquito client TLS PAP should pass against local server")
}
