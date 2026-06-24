// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/wxccs/tacacs/transport"
	"github.com/wxccs/tacacs/types"
)

// Shared client flags.
var (
	serverAddr string
	port       int
	secret     string
	tlsMode    bool
	caCert     string
	clientCert string
	clientKey  string
	sni        string
	debug      bool
	outputFmt  string
)

func addClientFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&serverAddr, "server", "127.0.0.1", "TACACS+ server address")
	cmd.Flags().IntVar(&port, "port", 49, "TACACS+ server port (300 for TLS)")
	cmd.Flags().StringVar(&secret, "secret", "", "shared secret (required for non-TLS)")
	cmd.Flags().BoolVar(&tlsMode, "tls", false, "use TLS 1.3")
	cmd.Flags().StringVar(&caCert, "ca-cert", "", "CA certificate PEM file (TLS)")
	cmd.Flags().StringVar(&clientCert, "client-cert", "", "client certificate PEM file (TLS)")
	cmd.Flags().StringVar(&clientKey, "client-key", "", "client private key PEM file (TLS)")
	cmd.Flags().StringVar(&sni, "sni", "", "TLS server name (SNI)")
	cmd.Flags().BoolVar(&debug, "debug", false, "enable debug logging")
	cmd.Flags().StringVar(&outputFmt, "output", "text", "output format: text|json")
}

// newLogger builds a Logger for the CLI. When debug is true, debug-level
// logging is enabled.
func newLogger(debug bool) types.Logger {
	base := logrus.New()
	base.SetOutput(os.Stderr)
	lvl := slog.LevelInfo
	if debug {
		lvl = slog.LevelDebug
	}
	return newLogrusLogger(base, lvl)
}

// dialTACACS opens a connection (legacy or TLS) to the configured server.
func dialTACACS(log types.Logger) (*transport.Conn, error) {
	addr := fmt.Sprintf("%s:%d", serverAddr, port)
	if !tlsMode {
		if secret == "" {
			return nil, fmt.Errorf("--secret is required for non-TLS connections")
		}
		types.WithFunc(log, "cmd.tacacs-cli.dialTACACS").Info("dialing over TCP (legacy obfuscation)", "addr", addr)
		return transport.Dial(context.Background(), "tcp", addr, []byte(secret))
	}
	cfg, err := buildTLSConfig()
	if err != nil {
		return nil, err
	}
	types.WithFunc(log, "cmd.tacacs-cli.dialTACACS").Info("dialing over TLS 1.3", "addr", addr)
	return transport.DialTLS(context.Background(), "tcp", addr, cfg)
}

func buildTLSConfig() (*tls.Config, error) {
	pool := x509.NewCertPool()
	if caCert != "" {
		ca, err := os.ReadFile(caCert)
		if err != nil {
			return nil, fmt.Errorf("read ca-cert: %w", err)
		}
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("failed to parse CA certificate %s", caCert)
		}
	}
	tcfg := transport.TLSConfig{ServerName: serverName(), CACertPool: pool}
	if clientCert != "" && clientKey != "" {
		cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key: %w", err)
		}
		tcfg.ClientCert = cert
	}
	return tcfg.ClientTLSConfig()
}

// serverName returns the SNI value, falling back to the server address.
func serverName() string {
	if sni != "" {
		return sni
	}
	return serverAddr
}

// printResult writes the result in text or JSON form. It returns nil when ok is
// true and an error otherwise so the CLI exit code reflects the outcome.
func printResult(result map[string]any, ok bool) error {
	switch outputFmt {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			return err
		}
	default:
		for k, v := range result {
			fmt.Printf("%s: %v\n", k, v)
		}
	}
	if !ok {
		os.Exit(1)
	}
	return nil
}

// readPasswordFromTerminal reads a line from stdin (terminal) without echo in
// production; here it reads a plain line for simplicity in non-interactive use.
func readPasswordFromTerminal() (string, error) {
	var line string
	if _, err := fmt.Fscanln(os.Stdin, &line); err != nil {
		return "", err
	}
	return line, nil
}
