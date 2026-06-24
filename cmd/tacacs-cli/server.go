// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"

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
			handler = &aaa.CompositeHandler{Auth: auth, Az: az}
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
	var metrics server.Metrics = server.NopMetrics()
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
				backends.auth.Reload(uc)
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

	for {
		c, err := ln.Accept()
		if err != nil {
			types.WithFunc(log, "cmd.tacacs-cli.runServer").Info("listener closed; exiting")
			return nil
		}
		conn := transport.Accept(c, mode(), []byte(secret))
		go func() {
			l := types.WithFunc(log, "server.ServeConn").With("peer", c.RemoteAddr().String())
			l.Info("connection accepted")
			if err := srv.ServeConn(context.Background(), conn); err != nil {
				l.Warn("session ended", "err", err)
			}
		}()
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
