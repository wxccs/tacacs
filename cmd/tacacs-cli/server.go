// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/wxccs/tacacs/cmd/tacacs-cli/aaa"
	"github.com/wxccs/tacacs/cmd/tacacs-cli/metrics/prom"
	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/transport"
	"github.com/wxccs/tacacs/types"
	"github.com/wxccs/tacacs/yang"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run a TACACS+ server with pluggable AAA backends",
	RunE:  runServerCmd,
}

var (
	listenAddr    string
	serverCfg     string
	metricsAddr   string
	accountingLog string
	useSyslog     bool
	watchConfig   bool
	maxConns      int
	readTimeout   time.Duration
	idleTimeout   time.Duration
	shutdownWait  time.Duration

	authBackend string

	authHTTPURL      string
	authHTTPInsecure bool

	authLDAPURL      string
	authLDAPBaseDN   string
	authLDAPBindDN   string
	authLDAPBindPw   string
	authLDAPFilter   string
	authLDAPStartTLS bool
	authLDAPInsecure bool

	authPAMService string
)

func init() {
	serverCmd.Flags().StringVar(&listenAddr, "listen", "127.0.0.1", "listen address")
	serverCmd.Flags().IntVar(&port, "port", 49, "listen port")
	serverCmd.Flags().StringVar(&secret, "secret", "", "shared secret (default 'testkey' if unset)")
	serverCmd.Flags().BoolVar(&tlsMode, "tls", false, "use TLS 1.3")
	serverCmd.Flags().StringVar(&caCert, "ca-cert", "", "CA certificate PEM file (TLS)")
	serverCmd.Flags().StringVar(&clientCert, "server-cert", "", "server certificate PEM file (TLS)")
	serverCmd.Flags().StringVar(&clientKey, "server-key", "", "server private key PEM file (TLS)")
	serverCmd.Flags().StringVar(&serverCfg, "config", "", "config file (YAML/JSON): user/policy or YANG server-list")
	serverCmd.Flags().BoolVar(&debug, "debug", false, "enable debug logging")
	serverCmd.Flags().StringVar(&metricsAddr, "metrics-addr", "", "HTTP server address for Prometheus metrics (e.g. :8080); empty disables")
	serverCmd.Flags().StringVar(&accountingLog, "accounting-log", "", "path to append accounting records as JSONL; empty disables persistence")
	serverCmd.Flags().BoolVar(&useSyslog, "syslog", false, "write accounting records to syslog (overrides --accounting-log when both are set)")
	serverCmd.Flags().BoolVar(&watchConfig, "watch-config", false, "watch the --config file for changes and reload (UserConfig only)")
	serverCmd.Flags().IntVar(&maxConns, "max-conns", 4096, "maximum concurrent connections; new connections beyond this are rejected (0 = unlimited)")
	serverCmd.Flags().DurationVar(&readTimeout, "read-timeout", 30*time.Second, "per-packet body read timeout (0 = disabled)")
	serverCmd.Flags().DurationVar(&idleTimeout, "idle-timeout", 0, "idle timeout waiting for the next packet on a connection (0 = disabled)")
	serverCmd.Flags().DurationVar(&shutdownWait, "shutdown-timeout", 10*time.Second, "max time to drain in-flight connections on shutdown")

	serverCmd.Flags().StringVar(&authBackend, "auth-backend", "local", "authentication backend: local|http|ldap|pam (authorization/accounting still come from --config)")
	serverCmd.Flags().StringVar(&authHTTPURL, "auth-http-url", "", "HTTP authenticator endpoint (must be https unless --auth-http-insecure)")
	serverCmd.Flags().BoolVar(&authHTTPInsecure, "auth-http-insecure", false, "permit a plain-http auth endpoint (localhost sidecar only)")
	serverCmd.Flags().StringVar(&authLDAPURL, "auth-ldap-url", "", "LDAP URL: ldaps://host:636 or ldap://host:389")
	serverCmd.Flags().StringVar(&authLDAPBaseDN, "auth-ldap-basedn", "", "LDAP search base DN")
	serverCmd.Flags().StringVar(&authLDAPBindDN, "auth-ldap-binddn", "", "LDAP service-account bind DN (empty = anonymous search)")
	serverCmd.Flags().StringVar(&authLDAPBindPw, "auth-ldap-bindpw", "", "LDAP service-account bind password")
	serverCmd.Flags().StringVar(&authLDAPFilter, "auth-ldap-filter", "", "LDAP user filter with one %s placeholder (default \"(uid=%s)\")")
	serverCmd.Flags().BoolVar(&authLDAPStartTLS, "auth-ldap-starttls", false, "upgrade ldap:// to TLS via StartTLS")
	serverCmd.Flags().BoolVar(&authLDAPInsecure, "auth-ldap-insecure", false, "permit cleartext ldap:// (sends bind password in clear)")
	serverCmd.Flags().StringVar(&authPAMService, "auth-pam-service", "tacacs", "PAM service name (file under /etc/pam.d); linux+cgo only")
	rootCmd.AddCommand(serverCmd)
}

// aaaBackends bundles the reloadable pieces of a CompositeHandler-driven
// server so the watch loop can refresh them in lockstep.
type aaaBackends struct {
	auth *aaa.BcryptAuthenticator
	az   *aaa.CommandAuthorizer
}

func runServerCmd(cmd *cobra.Command, args []string) error {
	log := newLogger(debug)
	if secret == "" {
		secret = "testkey"
	}

	// 1. Build the AAA handler. With --config pointing to a UserConfig we
	//    assemble BcryptAuthenticator + CommandAuthorizer + (optionally) an
	//    Accounter. Without --config we fall back to the static test handler.
	var handler server.Handler = &staticHandler{users: map[string]string{"admin": "admin123"}}
	var backends *aaaBackends
	if serverCfg != "" {
		uc, err := server.LoadUserConfig(serverCfg)
		if err != nil {
			// Fall back to the YANG server-list config (no users; static handler).
			if _, err2 := yang.Load(serverCfg); err2 != nil {
				return fmt.Errorf("load config: %w", err)
			}
			types.WithFunc(log, "cmd.tacacs-cli.runServer").Info("loaded servers from YANG config (user/policy features disabled)")
		} else {
			rules, err := userConfigToRules(uc)
			if err != nil {
				return fmt.Errorf("resolve config: %w", err)
			}
			auth := aaa.NewBcryptAuthenticator(uc)
			az, err := aaa.NewCommandAuthorizer(rules)
			if err != nil {
				return fmt.Errorf("compile authorizer rules: %w", err)
			}
			backends = &aaaBackends{auth: auth, az: az}
			// The authenticator may be overridden by an external backend
			// (--auth-backend). Authorization rules and accounting still come
			// from --config; only credential verification is delegated.
			var authn aaa.Authenticator = auth
			if authBackend != "local" {
				external, err := buildAuthenticator()
				if err != nil {
					return err
				}
				authn = external
				types.WithFunc(log, "cmd.tacacs-cli.runServer").Info("using external auth backend", "backend", authBackend)
			}
			handler = &aaa.CompositeHandler{Auth: authn, Az: az}
			types.WithFunc(log, "cmd.tacacs-cli.runServer").Info("loaded users from config", "users", len(uc.Users), "rules", len(rules))
		}
	}

	// 2. Attach an Accounter if requested. --syslog takes precedence over
	//    --accounting-log to avoid double-write surprises.
	if backends != nil {
		acc, closer, err := buildAccounter(log)
		if err != nil {
			return err
		}
		if acc != nil {
			backendsAuth := handler.(*aaa.CompositeHandler)
			backendsAuth.Ac = acc
			if closer != nil {
				defer closer()
			}
		}
	} else if accountingLog != "" || useSyslog {
		types.WithFunc(log, "cmd.tacacs-cli.runServer").Warn("accounting flags ignored without --config (static handler has no accounter)")
	}

	// 3. Build the Metrics implementation. --metrics-addr starts an HTTP
	//    server exporting /metrics; otherwise NopMetrics keeps the server
	//    silent.
	metrics := server.NopMetrics()
	var metricsServer *http.Server
	if metricsAddr != "" {
		m := prom.New()
		metrics = m
		metricsServer = &http.Server{Addr: metricsAddr, Handler: prom.Handler()}
		go func() {
			types.WithFunc(log, "cmd.tacacs-cli.runServer").Info("metrics server listening", "addr", metricsAddr)
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				types.WithFunc(log, "cmd.tacacs-cli.runServer").Error("metrics server failed", "err", err)
			}
		}()
		defer func() { _ = metricsServer.Shutdown(context.Background()) }()
	}

	// 4. Build the server with middleware. Order: Recovery (outermost) →
	//    Logging → Metrics → dispatch.
	srv := server.New(server.Config{
		Handler:          handler,
		Secret:           []byte(secret),
		Mode:             mode(),
		AllowUnencrypted: false,
		Metrics:          metrics,
		ReadTimeout:      readTimeout,
		IdleTimeout:      idleTimeout,
		Middleware: []server.Middleware{
			server.RecoveryMiddleware(log),
			server.LoggingMiddleware(log),
			server.MetricsMiddleware(metrics),
		},
	})
	defer srv.Close()

	// 5. Hot-reload the UserConfig when --watch-config is set. YANG
	//    server-list reload is not supported here; --watch-config only
	//    applies when --config is a UserConfig.
	if watchConfig {
		if backends == nil {
			types.WithFunc(log, "cmd.tacacs-cli.runServer").Warn("--watch-config set but no UserConfig loaded; nothing to watch")
		} else {
			watchCtx, watchCancel := context.WithCancel(context.Background())
			defer watchCancel()
			cb := func(path string) error {
				uc, err := server.LoadUserConfig(path)
				if err != nil {
					return err
				}
				rules, err := userConfigToRules(uc)
				if err != nil {
					return err
				}
				if err := backends.az.Reload(rules); err != nil {
					return err
				}
				if authBackend == "local" {
					backends.auth.Reload(uc)
				}
				types.WithFunc(log, "cmd.tacacs-cli.runServer").Info("config reloaded", "users", len(uc.Users), "rules", len(rules))
				return nil
			}
			if err := yang.WatchFile(watchCtx, serverCfg, log, cb); err != nil {
				return fmt.Errorf("watch config: %w", err)
			}
		}
	}

	// 6. Listen. SIGINT/SIGTERM triggers graceful shutdown.
	addr := fmt.Sprintf("%s:%d", listenAddr, port)
	ln, err := listen(addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	modeLabel := "TCP"
	if tlsMode {
		modeLabel = "TLS 1.3"
	}
	types.WithFunc(log, "cmd.tacacs-cli.runServer").Info("TACACS+ server listening", "addr", addr, "mode", modeLabel)

	// 6. Listen. SIGINT/SIGTERM triggers graceful shutdown: the listener is
	//    closed, in-flight connections are signalled via context cancellation
	//    and drained up to --shutdown-timeout, then force-closed.
	connCtx, connCancel := context.WithCancel(context.Background())
	defer connCancel()

	tracker := newConnTracker()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		types.WithFunc(log, "cmd.tacacs-cli.runServer").Info("shutting down")
		_ = ln.Close()
		if metricsServer != nil {
			_ = metricsServer.Shutdown(context.Background())
		}
	}()

	// sem caps concurrent connections; a nil sem means unlimited.
	var sem chan struct{}
	if maxConns > 0 {
		sem = make(chan struct{}, maxConns)
	}
	var wg sync.WaitGroup

	for {
		c, err := ln.Accept()
		if err != nil {
			// A temporary error (e.g. EMFILE under load) should not kill the
			// listener; back off briefly and retry. A permanent error
			// (listener closed on shutdown) ends the loop.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				metrics.IncAcceptError()
				time.Sleep(50 * time.Millisecond)
				continue
			}
			types.WithFunc(log, "cmd.tacacs-cli.runServer").Info("listener closed; draining")
			break
		}
		// Reject the connection when at capacity rather than queueing it,
		// bounding goroutine and memory growth under a connection flood.
		if sem != nil {
			select {
			case sem <- struct{}{}:
			default:
				types.WithFunc(log, "server.ServeConn").With("peer", c.RemoteAddr().String()).
					Warn("connection rejected: max-conns reached", "max_conns", maxConns)
				metrics.IncConnRejected("max_conns")
				_ = c.Close()
				continue
			}
		}
		conn := transport.Accept(c, mode(), []byte(secret))
		tracker.add(conn)
		metrics.IncConnAccepted()
		wg.Go(func() {
			defer tracker.remove(conn)
			if sem != nil {
				defer func() { <-sem }()
			}
			l := types.WithFunc(log, "server.ServeConn").With("peer", c.RemoteAddr().String())
			l.Info("connection accepted")
			if err := srv.ServeConn(connCtx, conn); err != nil {
				l.Warn("session ended", "err", err)
			}
		})
	}

	// Drain in-flight connections, bounded by --shutdown-timeout. On timeout
	// we cancel their contexts and close the sockets so ServeConn loops
	// unblock from any pending read and exit promptly.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		types.WithFunc(log, "cmd.tacacs-cli.runServer").Info("all connections drained")
	case <-time.After(shutdownWait):
		n := tracker.len()
		types.WithFunc(log, "cmd.tacacs-cli.runServer").Warn("drain timeout; force-closing in-flight connections", "timeout", shutdownWait, "remaining", n)
		connCancel()
		tracker.closeAll()
		<-done
	}
	return nil
}

// connTracker records in-flight connections so a graceful shutdown can
// force-close any that outlive the drain timeout (a blocking ReadPacket does
// not observe context cancellation on its own). It is safe for concurrent use.
type connTracker struct {
	mu    sync.Mutex
	conns map[*transport.Conn]struct{}
}

func newConnTracker() *connTracker {
	return &connTracker{conns: make(map[*transport.Conn]struct{})}
}

func (t *connTracker) add(c *transport.Conn) {
	t.mu.Lock()
	t.conns[c] = struct{}{}
	t.mu.Unlock()
}

func (t *connTracker) remove(c *transport.Conn) {
	t.mu.Lock()
	delete(t.conns, c)
	t.mu.Unlock()
}

func (t *connTracker) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns)
}

func (t *connTracker) closeAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for c := range t.conns {
		_ = c.Close()
	}
}

// listen opens a TCP or TLS listener on addr.
func listen(addr string) (net.Listener, error) {
	if tlsMode {
		tcfg, err := buildServerTLSConfig()
		if err != nil {
			return nil, err
		}
		return transport.ListenTLS("tcp", addr, tcfg)
	}
	return transport.Listen("tcp", addr)
}

// buildAccounter wires up the configured Accounter based on --syslog and
// --accounting-log. Returns nil when neither is set. The returned closer
// should be invoked at shutdown.
func buildAccounter(log types.Logger) (aaa.Accounter, func(), error) {
	if useSyslog {
		sa, err := aaa.NewSyslogAccounter("", "")
		if err != nil {
			return nil, nil, fmt.Errorf("dial syslog: %w", err)
		}
		types.WithFunc(log, "cmd.tacacs-cli.runServer").Info("accounting to syslog")
		return sa, func() { _ = sa.Close() }, nil
	}
	if accountingLog != "" {
		fa, err := aaa.NewFileAccounter(accountingLog)
		if err != nil {
			return nil, nil, err
		}
		types.WithFunc(log, "cmd.tacacs-cli.runServer").Info("accounting to file", "path", accountingLog)
		return fa, func() { _ = fa.Close() }, nil
	}
	return nil, nil, nil
}

// buildAuthenticator constructs the external authentication backend selected by
// --auth-backend. "local" is handled by the caller (bcrypt over --config) and
// is not valid here. Each backend enforces its own transport security.
func buildAuthenticator() (aaa.Authenticator, error) {
	switch authBackend {
	case "http":
		return aaa.NewHTTPAuthenticator(aaa.HTTPConfig{
			Endpoint:      authHTTPURL,
			AllowInsecure: authHTTPInsecure,
		})
	case "ldap":
		return aaa.NewLDAPAuthenticator(aaa.LDAPConfig{
			URL:           authLDAPURL,
			BindDN:        authLDAPBindDN,
			BindPassword:  authLDAPBindPw,
			BaseDN:        authLDAPBaseDN,
			UserFilter:    authLDAPFilter,
			StartTLS:      authLDAPStartTLS,
			AllowInsecure: authLDAPInsecure,
		})
	case "pam":
		return aaa.NewPAMAuthenticator(aaa.PAMConfig{Service: authPAMService})
	default:
		return nil, fmt.Errorf("unknown --auth-backend %q (want local|http|ldap|pam)", authBackend)
	}
}

// userConfigToRules translates a UserConfig into an ordered []aaa.CommandRule
// suitable for the global CommandAuthorizer. The translation merges:
//
//   - Structured rules from UserConfig.Resolve: each user's resolved Commands
//     (user-level + group-contributed) are appended in user declaration order.
//     Per-user rules are NOT scoped to the user here; the CommandAuthorizer
//     applies them uniformly. Deployments that need per-user rule isolation
//     should use server.ConfigHandler directly (it routes by User).
//   - Legacy Policy.DenyCommands and Policy.AllowCommands as glob-style
//     patterns, emitted LAST so structured rules take precedence.
//
// Glob patterns with a trailing " *" wildcard are converted to anchored
// regexes; other patterns match exactly. Special regex metacharacters in
// the literal parts are quoted so user-supplied patterns cannot inject
// regex operators.
func userConfigToRules(uc *server.UserConfig) ([]aaa.CommandRule, error) {
	resolved, err := uc.Resolve()
	if err != nil {
		return nil, err
	}
	rules := make([]aaa.CommandRule, 0)
	for _, u := range uc.Users {
		ru, ok := resolved[u.Username]
		if !ok {
			continue
		}
		rules = append(rules, ru.Commands...)
	}
	// Append legacy policy as a fallback layer.
	for _, pat := range uc.Policy.DenyCommands {
		rules = append(rules, aaa.CommandRule{
			Action:  aaa.ActionDeny,
			Pattern: globToRegex(pat),
		})
	}
	for _, pat := range uc.Policy.AllowCommands {
		rules = append(rules, aaa.CommandRule{
			Action:  aaa.ActionPermit,
			Pattern: globToRegex(pat),
		})
	}
	return rules, nil
}

// globToRegex converts a CLI glob pattern to an anchored Go regexp. A
// trailing " *" matches any suffix; otherwise the pattern is anchored as
// an exact match. Special regexp metacharacters in the literal parts are
// quoted so user-supplied patterns cannot inject regex operators.
func globToRegex(glob string) string {
	if strings.HasSuffix(glob, " *") {
		prefix := strings.TrimSuffix(glob, "*")
		return "^" + regexp.QuoteMeta(prefix) + ".*$"
	}
	return "^" + regexp.QuoteMeta(glob) + "$"
}

func mode() transport.Mode {
	if tlsMode {
		return transport.ModeTLS
	}
	return transport.ModeLegacy
}

func buildServerTLSConfig() (*tls.Config, error) {
	if clientCert == "" || clientKey == "" {
		return nil, fmt.Errorf("--server-cert and --server-key are required for TLS")
	}
	cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, fmt.Errorf("load server cert/key: %w", err)
	}
	pool := x509.NewCertPool()
	if caCert != "" {
		ca, err := os.ReadFile(caCert)
		if err != nil {
			return nil, err
		}
		pool.AppendCertsFromPEM(ca)
	} else {
		pool = nil // no client verification configured
	}
	return transport.ServerTLSConfig(cert, pool), nil
}

// staticHandler authenticates against a fixed user table.
type staticHandler struct {
	mu    sync.Mutex
	users map[string]string
}

func (h *staticHandler) Authenticate(ctx context.Context, ac server.AuthenContext, cont *server.AuthenContinue) (server.AuthenDecision, error) {
	h.mu.Lock()
	pw, ok := h.users[ac.Start.User]
	h.mu.Unlock()
	if !ok {
		return server.AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "unknown user"}, nil
	}
	if cont == nil {
		if ac.Start.Type == types.AuthenTypePAP {
			if string(ac.Start.Data) == pw {
				return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
			}
			return server.AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "bad password"}, nil
		}
		return server.AuthenDecision{Status: types.AuthenStatusGetPass, ServerMsg: "Password:"}, nil
	}
	if cont.UserMsg == pw {
		return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
	}
	return server.AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "bad password"}, nil
}

func (h *staticHandler) Authorize(ctx context.Context, ac server.AuthorContext) (server.AuthorDecision, error) {
	// Allow show commands; deny everything else.
	for _, a := range ac.Args {
		if a.Name == "cmd" && strings.HasPrefix(a.Value, "show") {
			return server.AuthorDecision{Status: types.AuthorStatusPassAdd}, nil
		}
	}
	return server.AuthorDecision{Status: types.AuthorStatusFail}, nil
}

func (h *staticHandler) Account(ctx context.Context, ac server.AcctContext) (server.AcctDecision, error) {
	return server.AcctDecision{Status: types.AcctStatusSuccess}, nil
}

// keep viper referenced; reserved for future richer config binding.
var _ = viper.New
