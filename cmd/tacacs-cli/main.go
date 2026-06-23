// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 The tacacs authors.
//
// This library is free software: you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library. If not, see <https://www.gnu.org/licenses/>.

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
