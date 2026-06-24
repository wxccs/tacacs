// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/wxccs/tacacs/client"
	"github.com/wxccs/tacacs/types"
)

var authzCmd = &cobra.Command{
	Use:   "authz",
	Short: "Send an authorization request to a TACACS+ server",
	RunE:  runAuthz,
}

var (
	authzService string
	authzCmdStr  string
	authzUser    string
)

func init() {
	addClientFlags(authzCmd)
	authzCmd.Flags().StringVar(&authzService, "service", "shell", "service to authorize")
	authzCmd.Flags().StringVar(&authzCmdStr, "cmd", "", "command to authorize")
	authzCmd.Flags().StringVar(&authzUser, "username", "", "username (required)")
	rootCmd.AddCommand(authzCmd)
}

func runAuthz(cmd *cobra.Command, args []string) error {
	if authzUser == "" {
		return fmt.Errorf("--username is required")
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
	req := client.AuthorRequest{
		Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser,
		Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin,
		User: authzUser, Port: "tacacs-cli",
		Args: []types.Argument{{Mandatory: true, Name: "service", Value: authzService}},
	}
	if authzCmdStr != "" {
		req.Args = append(req.Args, types.Argument{Mandatory: true, Name: "cmd", Value: authzCmdStr})
	}
	types.WithFunc(log, "cmd.tacacs-cli.runAuthz").Info("authorizing user", "user", authzUser, "service", authzService, "cmd", authzCmdStr)
	res, err := cl.Authorize(context.Background(), req)
	if err != nil {
		return fmt.Errorf("authorization failed: %w", err)
	}
	return printResult(map[string]any{
		"status":     res.Status.String(),
		"statusCode": int(res.Status),
		"serverMsg":  res.ServerMsg,
		"args":       argsToStrings(res.Args),
	}, res.Status == types.AuthorStatusPassAdd || res.Status == types.AuthorStatusPassRepl)
}

func argsToStrings(args []types.Argument) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = a.String()
	}
	return out
}
