// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

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

	types.WithFunc(log, "cmd.tacacs-cli.runAuth").Info("authenticating user", "user", authUser, "type", authType)
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
