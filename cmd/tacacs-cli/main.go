// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd is the tacacs-cli entry point.
var rootCmd = &cobra.Command{
	Use:   "tacacs-cli",
	Short: "TACACS+ command-line tool for client testing and server simulation",
	Long: `tacacs-cli exercises the tacacs library as both a TACACS+ client and a
lightweight test server.

Client mode subcommands (auth, authz, acct) connect to a TACACS+ server.
Server mode (server) starts a local test server driven by a config file.`,
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
