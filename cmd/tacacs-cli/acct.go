// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 Daniel Wu.
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
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/wxccs/tacacs/client"
	"github.com/wxccs/tacacs/types"
)

var acctCmd = &cobra.Command{
	Use:   "acct",
	Short: "Send an accounting record to a TACACS+ server",
	RunE:  runAcct,
}

var (
	acctAction string
	acctUser   string
)

func init() {
	addClientFlags(acctCmd)
	acctCmd.Flags().StringVar(&acctAction, "action", "start", "accounting action: start|stop|watchdog")
	acctCmd.Flags().StringVar(&acctUser, "username", "", "username (required)")
	rootCmd.AddCommand(acctCmd)
}

func runAcct(cmd *cobra.Command, args []string) error {
	if acctUser == "" {
		return fmt.Errorf("--username is required")
	}
	flags, err := parseAcctFlags(acctAction)
	if err != nil {
		return err
	}
	taskID := randomTaskID()
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
	req := client.AcctRequest{
		Flags: flags, Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser,
		Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin, User: acctUser, Port: "tacacs-cli",
		Args: []types.Argument{
			{Mandatory: true, Name: "task_id", Value: taskID},
			{Mandatory: true, Name: "service", Value: "shell"},
		},
	}
	log.WithFunc("cmd.tacacs-cli.runAcct").Infof("accounting %s user=%q task_id=%s", acctAction, acctUser, taskID)
	res, err := cl.Account(context.Background(), req)
	if err != nil {
		return fmt.Errorf("accounting failed: %w", err)
	}
	return printResult(map[string]any{
		"status":     res.Status.String(),
		"statusCode": int(res.Status),
		"serverMsg":  res.ServerMsg,
		"task_id":    taskID,
	}, res.Status == types.AcctStatusSuccess)
}

func parseAcctFlags(action string) (types.AcctFlags, error) {
	switch action {
	case "start":
		return types.AcctFlagStart, nil
	case "stop":
		return types.AcctFlagStop, nil
	case "watchdog":
		return types.AcctFlagWatchdog, nil
	default:
		return 0, fmt.Errorf("unknown accounting action %q", action)
	}
}

// randomTaskID returns a short hex task id from the cryptographic RNG.
func randomTaskID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
