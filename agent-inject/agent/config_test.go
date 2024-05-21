// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig(t *testing.T) {
	annotations := map[string]string{
		AnnotationAgentImage:                            "openbao",
		AnnotationOpenbaoService:                          "https://openbao:8200",
		AnnotationAgentStatus:                           "",
		AnnotationAgentRequestNamespace:                 "foobar",
		AnnotationOpenbaoRole:                             "foobar",
		AnnotationAgentPrePopulate:                      "true",
		AnnotationAgentPrePopulateOnly:                  "true",
		AnnotationOpenbaoTLSServerName:                    "foobar.server",
		AnnotationOpenbaoCACert:                           "ca-cert",
		AnnotationOpenbaoCAKey:                            "ca-key",
		AnnotationOpenbaoClientCert:                       "client-cert",
		AnnotationOpenbaoClientKey:                        "client-key",
		AnnotationOpenbaoSecretVolumePath:                 "/openbao/secrets",
		AnnotationProxyAddress:                          "http://proxy:3128",
		"openbao.openbao.org/agent-inject-secret-foo":   "db/creds/foo",
		"openbao.openbao.org/agent-inject-template-foo": "template foo",
		"openbao.openbao.org/agent-inject-secret-bar":   "db/creds/bar",

		// render this secret at a different path
		"openbao.openbao.org/agent-inject-secret-different-path":                "different-path",
		fmt.Sprintf("%s-%s", AnnotationOpenbaoSecretVolumePath, "different-path"): "/etc/container_environment",

		// render this secret from a template on disk
		"openbao.openbao.org/agent-inject-secret-with-file-template":                  "with-file-template",
		fmt.Sprintf("%s-%s", AnnotationAgentInjectTemplateFile, "with-file-template"): "/etc/file-template",

		"openbao.openbao.org/agent-inject-template-just-template": "just-template1",
		"openbao.openbao.org/secret-volume-path-just-template":    "/custom/path",
		"openbao.openbao.org/agent-inject-command-just-template":  "/tmp/smth.sh",
		"openbao.openbao.org/agent-inject-file-just-template":     ".env",
		"openbao.openbao.org/agent-inject-perms-just-template":    "0600",

		"openbao.openbao.org/agent-inject-template-file-just-template-file": "just-template-file",

		"openbao.openbao.org/agent-inject-command-bar": "pkill -HUP app",

		AnnotationAgentCacheEnable: "true",
	}

	pod := testPod(annotations)

	agentConfig := basicAgentConfig()
	err := Init(pod, agentConfig)
	if err != nil {
		t.Errorf("got error initialising pod, shouldn't have: %s", err)
	}

	agent, err := New(pod)
	if err != nil {
		t.Errorf("got error creating agent, shouldn't have: %s", err)
	}

	cfg, err := agent.newConfig(true)
	if err != nil {
		t.Errorf("got error creating Openbao config, shouldn't have: %s", err)
	}

	config := &Config{}
	if err := json.Unmarshal(cfg, config); err != nil {
		t.Errorf("got error unmarshalling Openbao config, shouldn't have: %s", err)
	}

	if config.ExitAfterAuth != true {
		t.Error("exit_after_auth should have been true, it wasn't")
	}

	if config.Openbao.TLSSkipVerify != false {
		t.Error("tls_skip_verify should have been false, it wasn't")
	}

	if config.Openbao.TLSServerName != annotations[AnnotationOpenbaoTLSServerName] {
		t.Errorf("tls_server_name: expected %s, got %s", annotations[AnnotationOpenbaoTLSServerName], config.Openbao.TLSServerName)
	}

	if config.Openbao.CACert != annotations[AnnotationOpenbaoCACert] {
		t.Errorf("ca_cert: expected %s, got %s", annotations[AnnotationOpenbaoCACert], config.Openbao.CACert)
	}

	if config.Openbao.CAPath != annotations[AnnotationOpenbaoCAKey] {
		t.Errorf("ca_key: expected %s, got %s", annotations[AnnotationOpenbaoCAKey], config.Openbao.CAPath)
	}

	if config.Openbao.ClientCert != annotations[AnnotationOpenbaoClientCert] {
		t.Errorf("client_cert: expected %s, got %s", annotations[AnnotationOpenbaoClientCert], config.Openbao.ClientCert)
	}

	if config.Openbao.ClientKey != annotations[AnnotationOpenbaoClientKey] {
		t.Errorf("client_key: expected %s, got %s", annotations[AnnotationOpenbaoClientKey], config.Openbao.ClientKey)
	}

	if config.AutoAuth.Method.Config["role"] != annotations[AnnotationOpenbaoRole] {
		t.Errorf("auto_auth role: expected role to be %s, got %s", annotations[AnnotationOpenbaoRole], config.AutoAuth.Method.Config["role"])
	}

	if config.AutoAuth.Method.Type != annotations[AnnotationOpenbaoAuthType] {
		t.Errorf("auto_auth mount type: expected type to be %s, got %s", annotations[AnnotationOpenbaoAuthType], config.AutoAuth.Method.Type)
	}

	if config.AutoAuth.Method.MountPath != annotations[AnnotationOpenbaoAuthPath] {
		t.Errorf("auto_auth mount path: expected path to be %s, got %s", annotations[AnnotationOpenbaoAuthPath], config.AutoAuth.Method.MountPath)
	}

	if len(config.Listener) != 0 || config.Cache != nil {
		t.Error("agent Cache should be disabled for init containers")
	}

	if len(config.Templates) != 6 {
		t.Errorf("expected 4 template, got %d", len(config.Templates))
	}

	for _, template := range config.Templates {
		if strings.Contains(template.Destination, "foo") {
			if template.Destination != "/openbao/secrets/foo" {
				t.Errorf("expected template destination to be %s, got %s", "/openbao/secrets/foo", template.Destination)
			}

			if template.Contents != "template foo" {
				t.Errorf("expected template contents to be %s, got %s", "template foo", template.Contents)
			}
		} else if strings.Contains(template.Destination, "bar") {
			if template.Destination != "/openbao/secrets/bar" {
				t.Errorf("expected template destination to be %s, got %s", "/openbao/secrets/bar", template.Destination)
			}

			if !strings.Contains(template.Contents, "with secret \"db/creds/bar\"") {
				t.Errorf("expected template contents to contain %s, got %s", "with secret \"db/creds/bar\"", template.Contents)
			}
			if !strings.Contains(template.Command, "pkill -HUP app") {
				t.Errorf("expected command contents to contain %s, got %s", "pkill -HUP app", template.Command)
			}
		} else if strings.Contains(template.Destination, "different-path") {
			if template.Destination != "/etc/container_environment/different-path" {
				t.Errorf("expected template destination to be %s, got %s", "/etc/container_environment", template.Destination)
			}
		} else if strings.Contains(template.Destination, "with-file-template") {
			if template.Source != "/etc/file-template" {
				t.Errorf("expected template file path to be %s, got %s", "/etc/file-template", template.Source)
			}
			if template.Contents != "" {
				t.Errorf("expected template contents to be empty, got %s", template.Contents)
			}
		} else if template.Contents == "just-template1" {
			if template.Destination != "/custom/path/.env" {
				t.Errorf("expected template destination to be %s, got %s", "/custom/path/.env", template.Destination)
			}
			if template.Perms != "0600" {
				t.Errorf("expected template perms to be %s, got %s", "0600", template.Perms)
			}
			if template.Command != "/tmp/smth.sh" {
				t.Errorf("expected template command to be %s, got %s", "/tmp/smth.sh", template.Command)
			}
		} else if template.Source == "just-template-file" {
			if template.Destination != "/openbao/secrets/just-template-file" {
				t.Errorf("expected template destination to be %s, got %s", "/openbao/secrets/just-template-file", template.Destination)
			}
		} else {
			t.Error("shouldn't have got here")
		}
	}
}

func TestFilePathAndName(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		destination string
	}{
		{
			"just secret",
			map[string]string{
				"openbao.openbao.org/agent-inject-secret-foo": "db/creds/foo",
			},
			secretVolumePath + "/foo",
		},
		{
			"with relative file path",
			map[string]string{
				"openbao.openbao.org/agent-inject-secret-foo": "db/creds/foo",
				"openbao.openbao.org/agent-inject-file-foo":   "nested/foofile",
			},
			secretVolumePath + "/nested/foofile",
		},
		{
			"with absolute file path",
			map[string]string{
				"openbao.openbao.org/agent-inject-secret-foo": "db/creds/foo",
				"openbao.openbao.org/agent-inject-file-foo":   "/special/volume/foofile",
			},
			secretVolumePath + "/special/volume/foofile",
		},
		{
			"with global volume mount set, long file name",
			map[string]string{
				"openbao.openbao.org/agent-inject-secret-foo": "db/creds/foo",
				"openbao.openbao.org/agent-inject-file-foo":   "foofile_name_is_very_very_very_long",
				"openbao.openbao.org/secret-volume-path":      "/new/mount/path",
			},
			"/new/mount/path/foofile_name_is_very_very_very_long",
		},
		{
			"with global volume mount set, absolute file path",
			map[string]string{
				"openbao.openbao.org/agent-inject-secret-foo": "db/creds/foo",
				"openbao.openbao.org/agent-inject-file-foo":   "/special/foofile",
				"openbao.openbao.org/secret-volume-path":      "/new/mount/path",
			},
			"/new/mount/path/special/foofile",
		},
		{
			"with secret volume mount set, relative file path",
			map[string]string{
				"openbao.openbao.org/agent-inject-secret-foo": "db/creds/foo",
				"openbao.openbao.org/agent-inject-file-foo":   "nested/foofile",
				"openbao.openbao.org/secret-volume-path-foo":  "/new/mount/path",
			},
			"/new/mount/path/nested/foofile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			if err != nil {
				t.Errorf("got error initialising pod, shouldn't have: %s", err)
			}

			agent, err := New(pod)
			if err != nil {
				t.Errorf("got error creating agent, shouldn't have: %s", err)
			}
			cfg, err := agent.newConfig(true)
			if err != nil {
				t.Errorf("got error creating Openbao config, shouldn't have: %s", err)
			}

			config := &Config{}
			if err := json.Unmarshal(cfg, config); err != nil {
				t.Errorf("got error unmarshalling Openbao config, shouldn't have: %s", err)
			}
			if config.Templates[0].Destination != tt.destination {
				t.Errorf("wrong destination: %s != %s", config.Templates[0].Destination, tt.destination)
			}
		})
	}
}

func TestFilePermission(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		permission  string
	}{
		{
			"just secret",
			map[string]string{
				"openbao.openbao.org/agent-inject-secret-foo": "db/creds/foo",
				"openbao.openbao.org/agent-inject-perms-foo":  "0600",
			},
			"0600",
		},
		{
			"just secret without permission",
			map[string]string{
				"openbao.openbao.org/agent-inject-secret-foo": "db/creds/foo",
			},
			"",
		},
		{
			"with relative file path",
			map[string]string{
				"openbao.openbao.org/agent-inject-secret-foo": "db/creds/foo",
				"openbao.openbao.org/agent-inject-file-foo":   "nested/foofile",
				"openbao.openbao.org/agent-inject-perms-foo":  "0600",
			},
			"0600",
		},
		{
			"with relative file path without permission",
			map[string]string{
				"openbao.openbao.org/agent-inject-secret-foo": "db/creds/foo",
				"openbao.openbao.org/agent-inject-file-foo":   "nested/foofile",
			},
			"",
		},
		{
			"with absolute file path",
			map[string]string{
				"openbao.openbao.org/agent-inject-secret-foo": "db/creds/foo",
				"openbao.openbao.org/agent-inject-file-foo":   "/special/volume/foofile",
				"openbao.openbao.org/agent-inject-perms-foo":  "0600",
			},
			"0600",
		},
		{
			"with absolute file path without permission",
			map[string]string{
				"openbao.openbao.org/agent-inject-secret-foo": "db/creds/foo",
				"openbao.openbao.org/agent-inject-file-foo":   "/special/volume/foofile",
			},
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			if err != nil {
				t.Errorf("got error initialising pod, shouldn't have: %s", err)
			}

			agent, err := New(pod)
			if err != nil {
				t.Errorf("got error creating agent, shouldn't have: %s", err)
			}
			cfg, err := agent.newConfig(true)
			if err != nil {
				t.Errorf("got error creating Openbao config, shouldn't have: %s", err)
			}

			config := &Config{}
			if err := json.Unmarshal(cfg, config); err != nil {
				t.Errorf("got error unmarshalling Openbao config, shouldn't have: %s", err)
			}
			if config.Templates[0].Perms != tt.permission {
				t.Errorf("wrong permission: %s != %s", config.Templates[0].Perms, tt.permission)
			}
		})
	}
}

func TestErrMissingKey(t *testing.T) {
	tests := []struct {
		name          string
		annotations   map[string]string
		errMissingKey bool
	}{
		{
			"just secret",
			map[string]string{
				"openbao.openbao.org/agent-inject-secret-foo":  "db/creds/foo",
				"openbao.openbao.org/error-on-missing-key-foo": "true",
			},
			true,
		},
		{
			"just secret without error on missing key",
			map[string]string{
				"openbao.openbao.org/agent-inject-secret-foo": "db/creds/foo",
			},
			false,
		},
		{
			"with false error on missing key",
			map[string]string{
				"openbao.openbao.org/agent-inject-secret-foo":  "db/creds/foo",
				"openbao.openbao.org/error-on-missing-key-foo": "false",
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			if err != nil {
				t.Errorf("got error initialising pod, shouldn't have: %s", err)
			}

			agent, err := New(pod)
			if err != nil {
				t.Errorf("got error creating agent, shouldn't have: %s", err)
			}
			cfg, err := agent.newConfig(true)
			if err != nil {
				t.Errorf("got error creating Openbao config, shouldn't have: %s", err)
			}

			config := &Config{}
			if err := json.Unmarshal(cfg, config); err != nil {
				t.Errorf("got error unmarshalling Openbao config, shouldn't have: %s", err)
			}
			if config.Templates[0].ErrMissingKey != tt.errMissingKey {
				t.Errorf("wrong permission: %v != %v", config.Templates[0].ErrMissingKey, tt.errMissingKey)
			}
		})
	}
}

func TestConfigOpenbaoAgentCacheNotEnabledByDefault(t *testing.T) {
	annotations := map[string]string{}

	pod := testPod(annotations)

	agentConfig := basicAgentConfig()
	err := Init(pod, agentConfig)
	if err != nil {
		t.Errorf("got error initialising pod, shouldn't have: %s", err)
	}

	agent, err := New(pod)
	if err != nil {
		t.Errorf("got error creating agent, shouldn't have: %s", err)
	}

	cfg, err := agent.newConfig(false)
	if err != nil {
		t.Errorf("got error creating Openbao config, shouldn't have: %s", err)
	}

	config := &Config{}
	if err := json.Unmarshal(cfg, config); err != nil {
		t.Errorf("got error unmarshalling Openbao config, shouldn't have: %s", err)
	}

	if len(config.Listener) != 0 || config.Cache != nil {
		t.Error("agent Cache should be not be enabled by default")
	}
}

func TestConfigOpenbaoAgentCache(t *testing.T) {
	annotations := map[string]string{
		AnnotationAgentCacheEnable:           "true",
		AnnotationAgentCacheUseAutoAuthToken: "force",
		AnnotationAgentCacheListenerPort:     "8100",
	}

	pod := testPod(annotations)

	agentConfig := basicAgentConfig()
	err := Init(pod, agentConfig)
	if err != nil {
		t.Errorf("got error initialising pod, shouldn't have: %s", err)
	}

	agent, err := New(pod)
	if err != nil {
		t.Errorf("got error creating agent, shouldn't have: %s", err)
	}

	cfg, err := agent.newConfig(false)
	if err != nil {
		t.Errorf("got error creating Openbao config, shouldn't have: %s", err)
	}

	config := &Config{}
	if err := json.Unmarshal(cfg, config); err != nil {
		t.Errorf("got error unmarshalling Openbao config, shouldn't have: %s", err)
	}

	if len(config.Listener) == 0 || config.Cache == nil {
		t.Error("agent Cache should be enabled")
	}

	if config.Cache.UseAutoAuthToken != "force" {
		t.Errorf("agent Cache use_auto_auth_token should be 'force', got %s instead", config.Cache.UseAutoAuthToken)
	}

	if config.Listener[0].Type != "tcp" {
		t.Errorf("agent Cache listener type should be tcp, got %s instead", config.Listener[0].Type)
	}

	if config.Listener[0].Address != "127.0.0.1:8100" {
		t.Errorf("agent Cache listener address should be 127.0.0.1:8100, got %s", config.Listener[0].Address)
	}

	if !config.Listener[0].TLSDisable {
		t.Error("agent Cache listener TLS should be disabled")
	}
}

func TestConfigOpenbaoAgentCache_persistent(t *testing.T) {
	tests := []struct {
		name              string
		annotations       map[string]string
		expectedInitCache bool
		expectedCache     *Cache
		expectedListeners []*Listener
	}{
		{
			name: "cache defaults",
			annotations: map[string]string{
				AnnotationAgentCacheEnable: "true",
			},
			expectedInitCache: true,
			expectedCache: &Cache{
				UseAutoAuthToken: "true",
				Persist: &CachePersist{
					Type: "kubernetes",
					Path: "/openbao/agent-cache",
				},
			},
			expectedListeners: []*Listener{
				{
					Type:       "tcp",
					Address:    "127.0.0.1:8200",
					TLSDisable: true,
				},
			},
		},
		{
			name: "exit on err",
			annotations: map[string]string{
				AnnotationAgentCacheEnable:    "true",
				AnnotationAgentCacheExitOnErr: "true",
			},
			expectedInitCache: true,
			expectedCache: &Cache{
				UseAutoAuthToken: "true",
				Persist: &CachePersist{
					Type:      "kubernetes",
					Path:      "/openbao/agent-cache",
					ExitOnErr: true,
				},
			},
			expectedListeners: []*Listener{
				{
					Type:       "tcp",
					Address:    "127.0.0.1:8200",
					TLSDisable: true,
				},
			},
		},
		{
			name: "just memory cache when only sidecar",
			annotations: map[string]string{
				AnnotationAgentCacheEnable: "true",
				AnnotationAgentPrePopulate: "false",
			},
			expectedInitCache: false,
			expectedCache: &Cache{
				UseAutoAuthToken: "true",
			},
			expectedListeners: []*Listener{
				{
					Type:       "tcp",
					Address:    "127.0.0.1:8200",
					TLSDisable: true,
				},
			},
		},
		{
			name: "no cache at all with only init container",
			annotations: map[string]string{
				AnnotationAgentCacheEnable:     "true",
				AnnotationAgentPrePopulateOnly: "true",
			},
			expectedInitCache: false,
			expectedCache:     nil,
			expectedListeners: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			require.NoError(t, err, "got error initialising pod: %s", err)

			agent, err := New(pod)
			require.NoError(t, err, "got error creating agent: %s", err)

			initCfg, err := agent.newConfig(true)
			require.NoError(t, err, "got error creating Openbao config: %s", err)

			initConfig := &Config{}
			err = json.Unmarshal(initCfg, initConfig)
			require.NoError(t, err, "got error unmarshalling Openbao init config: %s", err)

			if tt.expectedInitCache {
				assert.Equal(t, tt.expectedCache, initConfig.Cache)
				assert.Equal(t, tt.expectedListeners, initConfig.Listener)
			} else {
				assert.Nil(t, initConfig.Cache)
				assert.Nil(t, initConfig.Listener)
			}

			sidecarCfg, err := agent.newConfig(false)
			require.NoError(t, err, "got error creating Openbao sidecar config: %s", err)

			sidecarConfig := &Config{}
			err = json.Unmarshal(sidecarCfg, sidecarConfig)
			require.NoError(t, err, "got error unmarshalling Openbao sidecar config: %s", err)

			assert.Equal(t, tt.expectedCache, sidecarConfig.Cache)
			assert.Equal(t, tt.expectedListeners, sidecarConfig.Listener)
		})
	}
}

func TestConfigOpenbaoAgentTemplateConfig(t *testing.T) {
	tests := []struct {
		name                   string
		annotations            map[string]string
		expectedTemplateConfig *TemplateConfig
	}{
		{
			"exit_on_retry_failure true",
			map[string]string{
				AnnotationTemplateConfigExitOnRetryFailure: "true",
			},
			&TemplateConfig{
				ExitOnRetryFailure: true,
				MaxConnectionsPerHost: 0,
			},
		},
		{
			"exit_on_retry_failure false",
			map[string]string{
				AnnotationTemplateConfigExitOnRetryFailure: "false",
			},
			&TemplateConfig{
				ExitOnRetryFailure: false,
				MaxConnectionsPerHost: 0,
			},
		},
		{
			"static_secret_render_interval 10s",
			map[string]string{
				AnnotationTemplateConfigStaticSecretRenderInterval: "10s",
			},
			&TemplateConfig{
				ExitOnRetryFailure: true,
				StaticSecretRenderInterval: "10s",
				MaxConnectionsPerHost: 0,
			},
		},
		{
			"max_connections_per_host 100",
			map[string]string{
				AnnotationTemplateConfigMaxConnectionsPerHost: "100",
			},
			&TemplateConfig{
				ExitOnRetryFailure: true,
				MaxConnectionsPerHost: 100,
			},
		},
		{
			"template_config_empty",
			map[string]string{},
			&TemplateConfig{
				ExitOnRetryFailure: true,
				MaxConnectionsPerHost: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			require.NoError(t, err)

			agent, err := New(pod)
			require.NoError(t, err)
			cfg, err := agent.newConfig(true)
			require.NoError(t, err)

			config := &Config{}
			err = json.Unmarshal(cfg, config)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedTemplateConfig, config.TemplateConfig)
		})
	}
}

func TestInjectTokenSink(t *testing.T) {
	tokenHelperSink := &Sink{
		Type: "file",
		Config: map[string]interface{}{
			"path": TokenFile,
		},
	}
	injectTokenSink := &Sink{
		Type: "file",
		Config: map[string]interface{}{
			"path": secretVolumePath + "/token",
		},
	}

	tests := []struct {
		name          string
		annotations   map[string]string
		expectedSinks []*Sink
	}{
		{
			"token true",
			map[string]string{
				AnnotationAgentInjectToken: "true",
			},
			[]*Sink{tokenHelperSink, injectTokenSink},
		},
		{
			"token false",
			map[string]string{
				AnnotationAgentInjectToken: "false",
			},
			[]*Sink{tokenHelperSink},
		},
		{
			"custom secret volume path",
			map[string]string{
				AnnotationAgentInjectToken:      "true",
				AnnotationOpenbaoSecretVolumePath: "/new/secrets",
			},
			[]*Sink{
				tokenHelperSink,
				{
					Type: "file",
					Config: map[string]interface{}{
						"path": "/new/secrets/token",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			require.NoError(t, err)

			agent, err := New(pod)
			require.NoError(t, err)
			cfg, err := agent.newConfig(true)
			require.NoError(t, err)

			config := &Config{}
			err = json.Unmarshal(cfg, config)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedSinks, config.AutoAuth.Sinks)
		})
	}
}

func TestConfigAgentQuit(t *testing.T) {
	tests := []struct {
		name                   string
		annotations            map[string]string
		expectedAgentAPIConfig *AgentAPI
		expectedAddress        string
		expectedCache          *Cache
	}{
		{
			"enable_quit true",
			map[string]string{
				AnnotationAgentEnableQuit: "true",
			},
			&AgentAPI{EnableQuit: true},
			fmt.Sprintf("127.0.0.1:%s", DefaultAgentCacheListenerPort),
			&Cache{},
		},
		{
			"enable_quit true with custom port",
			map[string]string{
				AnnotationAgentEnableQuit:        "true",
				AnnotationAgentCacheListenerPort: "1234",
			},
			&AgentAPI{EnableQuit: true},
			fmt.Sprintf("127.0.0.1:%s", "1234"),
			&Cache{},
		},
		{
			"enable_quit false with no cache listener",
			nil,
			nil,
			fmt.Sprintf("127.0.0.1:%s", DefaultAgentCacheListenerPort),
			nil,
		},
		{
			"enable_quit true with existing cache listener",
			map[string]string{
				AnnotationAgentCacheEnable: "true",
				AnnotationAgentEnableQuit:  "true",
			},
			&AgentAPI{EnableQuit: true},
			fmt.Sprintf("127.0.0.1:%s", DefaultAgentCacheListenerPort),
			&Cache{
				UseAutoAuthToken: "true",
				Persist: &CachePersist{
					Type: "kubernetes",
					Path: "/openbao/agent-cache",
				},
			},
		},
		{
			"enable_quit false with existing cache listener",
			map[string]string{
				AnnotationAgentCacheEnable: "true",
				AnnotationAgentEnableQuit:  "false",
			},
			nil,
			fmt.Sprintf("127.0.0.1:%s", DefaultAgentCacheListenerPort),
			&Cache{
				UseAutoAuthToken: "true",
				Persist: &CachePersist{
					Type: "kubernetes",
					Path: "/openbao/agent-cache",
				},
			},
		},
		{
			"everything empty",
			map[string]string{},
			nil,
			DefaultAgentCacheListenerPort,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			require.NoError(t, err)

			agent, err := New(pod)
			require.NoError(t, err)
			// create sidecar config
			cfg, err := agent.newConfig(false)
			require.NoError(t, err)

			config := &Config{}
			err = json.Unmarshal(cfg, config)
			require.NoError(t, err)

			if tt.expectedAgentAPIConfig != nil {
				require.NotEmpty(t, config.Listener)
				require.NotNil(t, config.Listener[0].AgentAPI)
				assert.Equal(t, tt.expectedAgentAPIConfig, config.Listener[0].AgentAPI)
				assert.Equal(t, tt.expectedAddress, config.Listener[0].Address)
			} else {
				if len(config.Listener) > 0 {
					assert.Nil(t, config.Listener[0].AgentAPI)
					assert.Equal(t, tt.expectedAddress, config.Listener[0].Address)
				}
			}
			assert.Equal(t, tt.expectedCache, config.Cache)
		})
	}
}

func TestConfigTelemetry(t *testing.T) {
	tests := []struct {
		name              string
		annotations       map[string]string
		expectedTelemetry *Telemetry
	}{
		{
			"annotations that exercise all of the annotations",
			map[string]string{
				"openbao.openbao.org/agent-telemetry-usage_gauge_period":                     "10m",
				"openbao.openbao.org/agent-telemetry-maximum_gauge_cardinality":              "500",
				"openbao.openbao.org/agent-telemetry-disable_hostname":                       "false",
				"openbao.openbao.org/agent-telemetry-enable_hostname_label":                  "false",
				"openbao.openbao.org/agent-telemetry-lease_metrics_epsilon":                  "1h",
				"openbao.openbao.org/agent-telemetry-num_lease_metrics_buckets":              "168",
				"openbao.openbao.org/agent-telemetry-add_lease_metrics_namespace_labels":     "false",
				"openbao.openbao.org/agent-telemetry-filter_default":                         "true",
				"openbao.openbao.org/agent-telemetry-statsite_address":                       "https://foo.com",
				"openbao.openbao.org/agent-telemetry-statsd_address":                         "https://foo.com",
				"openbao.openbao.org/agent-telemetry-circonus_api_token":                     "foo",
				"openbao.openbao.org/agent-telemetry-circonus_api_app":                       "nomad",
				"openbao.openbao.org/agent-telemetry-circonus_api_url":                       "https://api.circonus.com/v2",
				"openbao.openbao.org/agent-telemetry-circonus_submission_interval":           "10s",
				"openbao.openbao.org/agent-telemetry-circonus_submission_url":                "https://api.circonus.com/v2",
				"openbao.openbao.org/agent-telemetry-circonus_check_id":                      "foo",
				"openbao.openbao.org/agent-telemetry-circonus_check_force_metric_activation": "false",
				"openbao.openbao.org/agent-telemetry-circonus_check_instance_id":             "foo:bar",
				"openbao.openbao.org/agent-telemetry-circonus_check_search_tag":              "foo:bar",
				"openbao.openbao.org/agent-telemetry-circonus_check_display_name":            "foo",
				"openbao.openbao.org/agent-telemetry-circonus_check_tags":                    "foo,bar",
				"openbao.openbao.org/agent-telemetry-circonus_broker_id":                     "foo",
				"openbao.openbao.org/agent-telemetry-circonus_broker_select_tag":             "foo:bar",
				"openbao.openbao.org/agent-telemetry-dogstatsd_addr":                         "https://foo.com",
				"openbao.openbao.org/agent-telemetry-dogstatsd_tags":                         `["foo:bar", "foo:baz"]`,
				"openbao.openbao.org/agent-telemetry-prometheus_retention_time":              "24h",
				"openbao.openbao.org/agent-telemetry-stackdriver_project_id":                 "foo",
				"openbao.openbao.org/agent-telemetry-stackdriver_location":                   "useast-1",
				"openbao.openbao.org/agent-telemetry-stackdriver_namespace":                  "foo",
				"openbao.openbao.org/agent-telemetry-stackdriver_debug_logs":                 "false",
				"openbao.openbao.org/agent-telemetry-prefix_filter":                          `["+openbao.token", "-openbao.expire", "+openbao.expire.num_leases"]`,
			},
			&Telemetry{
				UsageGaugePeriod:                   "10m",
				MaximumGaugeCardinality:            500,
				DisableHostname:                    false,
				EnableHostnameLabel:                false,
				LeaseMetricsEpsilon:                "1h",
				NumLeaseMetricsBuckets:             168,
				AddLeaseMetricsNamespaceLabels:     false,
				FilterDefault:                      true,
				PrefixFilter:                       []string{"+openbao.token", "-openbao.expire", "+openbao.expire.num_leases"},
				StatsiteAddress:                    "https://foo.com",
				StatsdAddress:                      "https://foo.com",
				CirconusApiToken:                   "foo",
				CirconusApiApp:                     "nomad",
				CirconusApiURL:                     "https://api.circonus.com/v2",
				CirconusSubmissionInterval:         "10s",
				CirconusSubmissionURL:              "https://api.circonus.com/v2",
				CirconusCheckID:                    "foo",
				CirconusCheckForceMetricActivation: false,
				CirconusCheckInstanceID:            "foo:bar",
				CirconusCheckSearchTag:             "foo:bar",
				CirconusCheckDisplayName:           "foo",
				CirconusCheckTags:                  "foo,bar",
				CirconusBrokerID:                   "foo",
				CirconusBrokerSelectTag:            "foo:bar",
				DogstatsdAddr:                      "https://foo.com",
				DogstatsdTags:                      []string{"foo:bar", "foo:baz"},
				PrometheusRetentionTime:            "24h",
				StackdriverProjectID:               "foo",
				StackdriverLocation:                "useast-1",
				StackdriverNamespace:               "foo",
				StackdriverDebugLogs:               false,
			},
		},
		{
			"everything empty",
			map[string]string{},
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod(tt.annotations)

			agentConfig := basicAgentConfig()
			err := Init(pod, agentConfig)
			require.NoError(t, err)

			agent, err := New(pod)
			require.NoError(t, err)
			// create sidecar config
			cfg, err := agent.newConfig(false)
			require.NoError(t, err)

			config := &Config{}
			err = json.Unmarshal(cfg, config)
			require.NoError(t, err)

			require.Equal(t, tt.expectedTelemetry, config.Telemetry)
		})
	}
}
