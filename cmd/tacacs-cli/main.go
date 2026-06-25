// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version, commit, date are overridden at build time via -ldflags
// "-X main.version=..." (see .goreleaser.yml). Defaults are used when the
// binary is built with plain `go build`.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// rootCmd is the tacacs-cli entry point.
var rootCmd = &cobra.Command{
	Use:     "tacacs-cli",
	Short:   "TACACS+ command-line tool for client testing and server simulation",
	Version: version,
	Long: `tacacs-cli exercises the tacacs library as both a TACACS+ client and a
lightweight test server.

Client mode subcommands (auth, authz, acct) connect to a TACACS+ server.
Server mode (server) starts a local test server driven by a config file.`,
}

func init() {
	rootCmd.SetVersionTemplate(`{{.Name}} version {{.Version}} (commit: ` + commit + `, built: ` + date + `)
`)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
