// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"

	cmdInjector "github.com/openbao/openbao-k8s/subcommand/injector"
	cmdVersion "github.com/openbao/openbao-k8s/subcommand/version"
	"github.com/openbao/openbao-k8s/version"
	"github.com/mitchellh/cli"
)

var Commands map[string]cli.CommandFactory

func init() {
	ui := &cli.BasicUi{Writer: os.Stdout, ErrorWriter: os.Stderr}

	Commands = map[string]cli.CommandFactory{
		"agent-inject": func() (cli.Command, error) {
			return &cmdInjector.Command{UI: ui}, nil
		},
		"version": func() (cli.Command, error) {
			return &cmdVersion.Command{UI: ui, Version: version.Version}, nil
		},
	}
}
