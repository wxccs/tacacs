// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package yang

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"

	"github.com/wxccs/tacacs/errors"
)

// useYAMLTags is a viper decoder option that makes mapstructure read the "yaml"
// struct tag instead of the default "mapstructure" tag, so the same struct tags
// serve both file formats and decoding.
func useYAMLTags(dc *mapstructure.DecoderConfig) {
	dc.TagName = "yaml"
}

// Load reads a TACACS+ configuration from a YAML or JSON file path and returns
// the validated Config. The file format is inferred from the extension (.yaml,
// .yml, .json). The YAML/JSON mirrors the ietf-system-tacacs-plus "tacacs-plus"
// container, optionally wrapped under a "tacacs-plus" key.
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}
	cfg, err := unmarshal(v)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadFromBytes parses configuration from raw YAML or JSON bytes (format
// inferred from the config type) and returns the validated Config.
func LoadFromBytes(data []byte, format string) (*Config, error) {
	v := viper.New()
	v.SetConfigType(format)
	if err := v.ReadConfig(bytes.NewReader(data)); err != nil {
		return nil, err
	}
	cfg, err := unmarshal(v)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// unmarshal decodes the viper view into Config, then normalizes the
// server-type string(s) into the ServerType bits (mapstructure cannot do this
// automatically).
func unmarshal(v *viper.Viper) (*Config, error) {
	// Allow either a top-level "tacacs-plus" wrapper or a bare model.
	root := v
	if sub := v.Sub("tacacs-plus"); sub != nil {
		root = sub
	}

	cfg := &Config{}
	if err := root.UnmarshalKey("server", &cfg.Servers, useYAMLTags); err != nil {
		return nil, errors.NewValidationError("server", "failed to decode server list", err)
	}
	// Normalize the raw server-type string(s) into ServerType bits.
	for i := range cfg.Servers {
		cfg.Servers[i].ServerType = parseServerType(cfg.Servers[i].RawServerType)
	}
	if err := root.UnmarshalKey("client-credentials", &cfg.ClientCredentials, useYAMLTags); err != nil {
		return nil, err
	}
	if err := root.UnmarshalKey("server-credentials", &cfg.ServerCredentials, useYAMLTags); err != nil {
		return nil, err
	}
	return cfg, nil
}

// parseServerType converts a server-type value (string or list of strings) into
// the ServerType bits.
func parseServerType(raw any) ServerType {
	var st ServerType
	add := func(s string) {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "authentication":
			st |= ServerTypeAuthentication
		case "authorization":
			st |= ServerTypeAuthorization
		case "accounting":
			st |= ServerTypeAccounting
		}
	}
	switch v := raw.(type) {
	case string:
		add(v)
	case []any:
		for _, x := range v {
			add(fmt.Sprint(x))
		}
	}
	return st
}
