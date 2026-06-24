// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/transport"
	"github.com/wxccs/tacacs/types"
	"github.com/wxccs/tacacs/yang"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run a lightweight TACACS+ test server",
	RunE:  runServerCmd,
}

var (
	listenAddr string
	serverCfg  string
)

func init() {
	serverCmd.Flags().StringVar(&listenAddr, "listen", "127.0.0.1", "listen address")
	serverCmd.Flags().IntVar(&port, "port", 49, "listen port")
	serverCmd.Flags().StringVar(&secret, "secret", "", "shared secret (default 'testkey' if unset)")
	serverCmd.Flags().BoolVar(&tlsMode, "tls", false, "use TLS 1.3")
	serverCmd.Flags().StringVar(&caCert, "ca-cert", "", "CA certificate PEM file (TLS)")
	serverCmd.Flags().StringVar(&clientCert, "server-cert", "", "server certificate PEM file (TLS)")
	serverCmd.Flags().StringVar(&clientKey, "server-key", "", "server private key PEM file (TLS)")
	serverCmd.Flags().StringVar(&serverCfg, "config", "", "config file (YAML/JSON) defining users and policies")
	serverCmd.Flags().BoolVar(&debug, "debug", false, "enable debug logging")
	rootCmd.AddCommand(serverCmd)
}

func runServerCmd(cmd *cobra.Command, args []string) error {
	log := newLogger(debug)
	if secret == "" {
		secret = "testkey"
	}

	var handler server.Handler = &staticHandler{users: map[string]string{"admin": "admin123"}}
	if serverCfg != "" {
		// The config file may be a user/policy config (UserConfig) or a YANG
		// server-list config. Try the user config first.
		uc, err := server.LoadUserConfig(serverCfg)
		if err != nil {
			// Fall back to the YANG server-list config (no users; static handler).
			cfg, err2 := yang.Load(serverCfg)
			if err2 != nil {
				return fmt.Errorf("load config: %w", err)
			}
			types.WithFunc(log, "cmd.tacacs-cli.runServer").Info("loaded servers from YANG config", "count", len(cfg.Servers))
		} else {
			handler = server.NewConfigHandler(uc)
			types.WithFunc(log, "cmd.tacacs-cli.runServer").Info("loaded users from config", "count", len(uc.Users))
		}
	}

	srv := server.New(server.Config{Handler: handler, Secret: []byte(secret), Mode: mode(), AllowUnencrypted: false})

	addr := fmt.Sprintf("%s:%d", listenAddr, port)
	var ln net.Listener
	var err error
	if tlsMode {
		tcfg, err := buildServerTLSConfig()
		if err != nil {
			return err
		}
		ln, err = transport.ListenTLS("tcp", addr, tcfg)
		if err != nil {
			return err
		}
		types.WithFunc(log, "cmd.tacacs-cli.runServer").Info("TACACS+ TLS 1.3 test server listening", "addr", addr)
	} else {
		ln, err = transport.Listen("tcp", addr)
		if err != nil {
			return err
		}
		types.WithFunc(log, "cmd.tacacs-cli.runServer").Info("TACACS+ test server listening", "addr", addr)
	}
	defer ln.Close()

	for {
		c, err := ln.Accept()
		if err != nil {
			return err
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
