// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"

	tacerrs "github.com/wxccs/tacacs/errors"
)

func TestArgumentString(t *testing.T) {
	assert.Equal(t, "service=shell",
		Argument{Mandatory: true, Name: "service", Value: "shell"}.String())
	assert.Equal(t, "cmd*show",
		Argument{Mandatory: false, Name: "cmd", Value: "show"}.String())
	assert.Equal(t, "cmd=",
		Argument{Mandatory: true, Name: "cmd", Value: ""}.String())
	assert.Equal(t, "cmd*",
		Argument{Mandatory: false, Name: "cmd", Value: ""}.String())
}

func TestParseArgument(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		mandatory bool
		argName   string
		value     string
	}{
		{"mandatory", "service=shell", true, "service", "shell"},
		{"optional", "cmd*show", false, "cmd", "show"},
		{"value with separator", "cmd=a=b", true, "cmd", "a=b"},
		{"first separator wins optional", "cmd*a=b", false, "cmd", "a=b"},
		{"empty value", "cmd=", true, "cmd", ""},
		{"empty value optional", "cmd*", false, "cmd", ""},
		{"single char name", "a=b", true, "a", "b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := ParseArgument(c.in)
			assert.NoError(t, err)
			assert.Equal(t, c.mandatory, a.Mandatory)
			assert.Equal(t, c.argName, a.Name)
			assert.Equal(t, c.value, a.Value)
			assert.Equal(t, c.in, a.String())
		})
	}
}

func TestParseArgumentErrors(t *testing.T) {
	_, err := ParseArgument("noseparator")
	assert.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))

	_, err = ParseArgument("=value") // empty name
	assert.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))

	_, err = ParseArgument("")
	assert.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))

	_, err = ParseArgument("*")
	assert.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))
}
