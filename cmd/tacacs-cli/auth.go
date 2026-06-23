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
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/wxccs/tacacs/client"
	"github.com/wxccs/tacacs/types"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authenticate against a TACACS+ server",
	RunE:  runAuth,
}

func init() {
	addClientFlags(authCmd)
	authCmd.Flags().StringVar(&authUser, "username", "", "username (required)")
	authCmd.Flags().StringVar(&authPassword, "password", "", "password (required for PAP)")
	authCmd.Flags().StringVar(&authType, "type", "ascii", "authentication type: ascii|pap|chap|mschap|mschapv2")
	rootCmd.AddCommand(authCmd)
}

var (
	authUser     string
	authPassword string
	authType     string
)

func runAuth(cmd *cobra.Command, args []string) error {
	if authUser == "" {
		return fmt.Errorf("--username is required")
	}
	at, err := parseAuthenType(authType)
	if err != nil {
		return err
	}
	log := newLogger(debug)

	conn, err := dialTACACS(log)
	if err != nil {
		return err
	}
	defer conn.Close()

	cl, err := client.New(conn)
	if err != nil {
		return err
	}

	req := client.AuthenRequest{
		Action: types.AuthenLogin, Type: at, Service: types.AuthenServiceLogin,
		User: authUser, Port: "tacacs-cli", Data: []byte(authPassword),
	}
	// ASCII interactive: prompt for password on the terminal.
	var contFn func(reply client.AuthenReply) (string, error)
	if at == types.AuthenTypeASCII && authPassword == "" {
		contFn = func(reply client.AuthenReply) (string, error) {
			fmt.Fprintln(os.Stderr, reply.ServerMsg)
			return readPasswordFromTerminal()
		}
	}

	log.WithFunc("cmd.tacacs-cli.runAuth").Infof("authenticating user %q via %s", authUser, authType)
	reply, err := cl.Authenticate(context.Background(), req, contFn)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	return printResult(map[string]any{
		"status":     reply.Status.String(),
		"statusCode": int(reply.Status),
		"serverMsg":  reply.ServerMsg,
		"flags":      reply.Flags,
	}, reply.Status == types.AuthenStatusPass)
}

func parseAuthenType(s string) (types.AuthenType, error) {
	switch s {
	case "ascii":
		return types.AuthenTypeASCII, nil
	case "pap":
		return types.AuthenTypePAP, nil
	case "chap":
		return types.AuthenTypeCHAP, nil
	case "mschap":
		return types.AuthenTypeMSCHAP, nil
	case "mschapv2":
		return types.AuthenTypeMSCHAPv2, nil
	default:
		return 0, fmt.Errorf("unknown authentication type %q", s)
	}
}
