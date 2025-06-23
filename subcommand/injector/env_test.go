// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package injector

import (
	"os"
	"testing"
  	"github.com/stretchr/testify/require"
)

func TestReadBaoVariable_Vault(t *testing.T) {
	actual := "example_value"
	os.Setenv("AGENT_INJECT_VAULT_TEST", actual)
	expected := ReadBaoVariable("AGENT_INJECT_BAO_TEST")
	require.Equal(t, actual, expected, "bad: Failed to Read Enviroment Variable actual: %s expected: %s", actual, expected)
}

func TestReadBaoVariable_Bao(t *testing.T) {
	actual := "example_value"
	os.Setenv("AGENT_INJECT_BAO_TEST", actual)
	expected := ReadBaoVariable("AGENT_INJECT_BAO_TEST")
	require.Equal(t, actual, expected, "bad: Failed to Read Enviroment Variable actual: %s expected: %s", actual, expected)
}

func TestReadBaoVariable_BaoWins(t *testing.T) {
	actual := "example_value"
	os.Setenv("AGENT_INJECT_VAULT_TEST", actual+"_not_valid")
	os.Setenv("AGENT_INJECT_BAO_TEST", actual)
	expected := ReadBaoVariable("AGENT_INJECT_BAO_TEST")
	require.Equal(t, actual, expected, "bad: Failed to Read Enviroment Variable actual: %s expected: %s", actual, expected)
}
