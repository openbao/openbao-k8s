// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"os"
	"strings"
)

func ReadBaoVariable(name string) string {
	nonPrefixedName := strings.Replace(name, "AGENT_INJECT_BAO_", "", 1)
	prefixes := [2]string{"AGENT_INJECT_BAO_", "AGENT_INJECT_VAULT_"}
	for _, prefix := range prefixes {
		searchName := prefix + nonPrefixedName
		result := os.Getenv(searchName)
		if result != "" {
			return result
		}
	}
	return ""
}
