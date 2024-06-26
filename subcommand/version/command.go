// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package version

import (
	"fmt"

	"github.com/mitchellh/cli"
)

type Command struct {
	UI      cli.Ui
	Version string
}

func (c *Command) Run(_ []string) int {
	c.UI.Output(fmt.Sprintf("openbao-k8s %s", c.Version))
	return 0
}

func (c *Command) Synopsis() string {
	return "Prints the version"
}

func (c *Command) Help() string {
	return ""
}
