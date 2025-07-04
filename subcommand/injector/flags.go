// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package injector

import (
	"flag"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/tlsutil"
	"github.com/openbao/openbao-k8s/agent-inject/agent"
	"github.com/openbao/openbao-k8s/helper/flags"
	"github.com/kelseyhightower/envconfig"
)

const (
	DefaultLogLevel      = "info"
	DefaultLogFormat     = "standard"
	defaultTLSMinVersion = "tls12"
	EnvBaoAddress        = "AGENT_INJECT_BAO_ADDR"
	EnvBaoCACertBytes    = "AGENT_INJECT_BAO_CACERT_BYTES"
	EnvBaoImage          = "AGENT_INJECT_BAO_IMAGE"
	EnvBaoAuthType       = "AGENT_INJECT_BAO_AUTH_TYPE"
	EnvBaoAuthPath       = "AGENT_INJECT_BAO_AUTH_PATH"
	EnvBaoNamespace      = "AGENT_INJECT_BAO_NAMESPACE"
)

// Specification are the supported environment variables, prefixed with
// AGENT_INJECT.  The names of the variables in the struct are split using
// camel case: Specification.OpenbaoAddr = AGENT_INJECT_BAO_ADDR
type Specification struct {
	// Listen is the AGENT_INJECT_LISTEN environment variable.
	Listen string `split_words:"true" `

	// LogLevel is the AGENT_INJECT_LOG_LEVEL environment variable.
	LogLevel string `split_words:"true"`

	// LogFormat is the AGENT_INJECT_LOG_FORMAT environment variable
	LogFormat string `split_words:"true"`

	// TemplateConfigExitOnRetryFailure is the
	// AGENT_INJECT_TEMPLATE_CONFIG_EXIT_ON_RETRY_FAILURE environment variable.
	TemplateConfigExitOnRetryFailure string `split_words:"true"`

	// TemplateConfigStaticSecretRenderInterval is the
	// AGENT_INJECT_TEMPLATE_STATIC_SECRET_RENDER_INTERVAL environment variable.
	TemplateConfigStaticSecretRenderInterval string `envconfig:"AGENT_INJECT_TEMPLATE_STATIC_SECRET_RENDER_INTERVAL"`

	// TemplateConfigMaxConnectionsPerHost is the
	// AGENT_INJECT_TEMPLATE_MAX_CONNECTIONS_PER_HOST environment variable.
	TemplateConfigMaxConnectionsPerHost string `envconfig:"AGENT_INJECT_TEMPLATE_MAX_CONNECTIONS_PER_HOST"`

	// TLSAuto is the AGENT_INJECT_TLS_AUTO environment variable.
	TLSAuto string `envconfig:"tls_auto"`

	// TLSAutoHosts is the AGENT_INJECT_TLS_AUTO_HOSTS environment variable.
	TLSAutoHosts string `envconfig:"tls_auto_hosts"`

	// TLSCertFile is the AGENT_INJECT_TLS_CERT_FILE environment variable.
	TLSCertFile string `envconfig:"tls_cert_file"`

	// TLSKeyFile is the AGENT_INJECT_TLS_KEY_FILE environment variable.
	TLSKeyFile string `envconfig:"tls_key_file"`

	// ProxyAddr is the AGENT_INJECT_PROXY_ADDR environment variable.
	ProxyAddr string `split_words:"true"`

	// RevokeOnShutdown is AGENT_INJECT_REVOKE_ON_SHUTDOWN environment variable.
	RevokeOnShutdown string `split_words:"true"`

	// RunAsUser is the AGENT_INJECT_RUN_AS_USER environment variable. (uid)
	RunAsUser string `envconfig:"AGENT_INJECT_RUN_AS_USER"`

	// RunAsGroup is the AGENT_INJECT_RUN_AS_GROUP environment variable. (gid)
	RunAsGroup string `envconfig:"AGENT_INJECT_RUN_AS_GROUP"`

	// RunAsSameUser is the AGENT_INJECT_RUN_AS_SAME_USER environment variable.
	RunAsSameUser string `envconfig:"AGENT_INJECT_RUN_AS_SAME_USER"`

	// SetSecurityContext is the AGENT_INJECT_SET_SECURITY_CONTEXT environment variable.
	SetSecurityContext string `envconfig:"AGENT_INJECT_SET_SECURITY_CONTEXT"`

	// TelemetryPath is the AGENT_INJECT_TELEMETRY_PATH environment variable.
	TelemetryPath string `split_words:"true"`

	// UseLeaderElector is the AGENT_INJECT_USE_LEADER_ELECTOR environment variable.
	UseLeaderElector string `split_words:"true"`

	// DefaultTemplate is the AGENT_INJECT_DEFAULT_TEMPLATE environment variable.
	DefaultTemplate string `split_words:"true"`

	// ResourceRequestCPU is the AGENT_INJECT_CPU_REQUEST environment variable.
	ResourceRequestCPU string `envconfig:"AGENT_INJECT_CPU_REQUEST"`

	// ResourceRequestMem is the AGENT_INJECT_MEM_REQUEST environment variable.
	ResourceRequestMem string `envconfig:"AGENT_INJECT_MEM_REQUEST"`

	// ResourceRequestEphemeral is the AGENT_INJECT_EPHEMERAL_REQUEST environment variable.
	ResourceRequestEphemeral string `envconfig:"AGENT_INJECT_EPHEMERAL_REQUEST"`

	// ResourceLimitCPU is the AGENT_INJECT_CPU_LIMIT environment variable.
	ResourceLimitCPU string `envconfig:"AGENT_INJECT_CPU_LIMIT"`

	// ResourceLimitMem is the AGENT_INJECT_MEM_LIMIT environment variable.
	ResourceLimitMem string `envconfig:"AGENT_INJECT_MEM_LIMIT"`

	// ResourceLimitEphemeral is the AGENT_INJECT_EPHEMERAL_LIMIT environment variable.
	ResourceLimitEphemeral string `envconfig:"AGENT_INJECT_EPHEMERAL_LIMIT"`

	// TLSMinVersion is the AGENT_INJECT_TLS_MIN_VERSION environment variable
	TLSMinVersion string `envconfig:"tls_min_version"`

	// TLSCipherSuites is the AGENT_INJECT_TLS_CIPHER_SUITES environment variable
	TLSCipherSuites string `envconfig:"tls_cipher_suites"`

	// AuthMinBackoff is the AGENT_MIN_BACKOFF environment variable
	AuthMinBackoff string `envconfig:"AGENT_INJECT_AUTH_MIN_BACKOFF"`

	// AuthMaxBackoff is the AGENT_MAX_BACKOFF environment variable
	AuthMaxBackoff string `envconfig:"AGENT_INJECT_AUTH_MAX_BACKOFF"`

	// DisableIdleConnections is the AGENT_INJECT_DISABLE_IDLE_CONNECTIONS environment variable
	DisableIdleConnections string `split_words:"true"`

	// DisableKeepAlives is the AGENT_INJECT_DISABLE_KEEP_ALIVES environment variable
	DisableKeepAlives string `split_words:"true"`
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.StringVar(&c.flagListen, "listen", ":8080", "Address to bind listener to.")
	c.flagSet.StringVar(&c.flagLogLevel, "log-level", DefaultLogLevel, "Log verbosity level. Supported values "+
		`(in order of detail) are "trace", "debug", "info", "warn", and "err".`)
	c.flagSet.StringVar(&c.flagLogFormat, "log-format", DefaultLogFormat, "Log output format. "+
		`Supported log formats: "standard", "json".`)
	c.flagSet.BoolVar(&c.flagExitOnRetryFailure, "template-config-exit-on-retry-failure", agent.DefaultTemplateConfigExitOnRetryFailure,
		fmt.Sprintf("Value for Agent's template_config.exit_on_retry_failure. Defaults to %t.", agent.DefaultTemplateConfigExitOnRetryFailure))
	c.flagSet.StringVar(&c.flagStaticSecretRenderInterval, "template-static-secret-render-interval", "",
		"Value for Agent's template_config.exit_on_retry_failure.")
	c.flagSet.StringVar(&c.flagAutoName, "tls-auto", "",
		"MutatingWebhookConfiguration name. If specified, will auto generate cert bundle.")
	c.flagSet.StringVar(&c.flagAutoHosts, "tls-auto-hosts", "",
		"Comma-separated hosts for auto-generated TLS cert. If specified, will auto generate cert bundle.")
	c.flagSet.StringVar(&c.flagCertFile, "tls-cert-file", "",
		"PEM-encoded TLS certificate to serve. If blank, will generate random cert.")
	c.flagSet.StringVar(&c.flagKeyFile, "tls-key-file", "",
		"PEM-encoded TLS private key to serve. If blank, will generate random cert.")
	c.flagSet.StringVar(&c.flagBaoImage, "bao-image", agent.DefaultBaoImage,
		fmt.Sprintf("Docker image for Openbao. Defaults to %q.", agent.DefaultBaoImage))
	c.flagSet.StringVar(&c.flagBaoService, "bao-address", "",
		"Address of the Openbao server.")
	c.flagSet.StringVar(&c.flagBaoCACertBytes, "bao-cacert-bytes", "",
		"CA certificate to trust for TLS with Openbao, specified as a PEM-encoded certificate or bundle. "+
			"The multi-line PEM contents may optionally be base64 encoded to avoid line breaks.")
	c.flagSet.StringVar(&c.flagProxyAddress, "proxy-address", "",
		"HTTP proxy address used to talk to the Openbao service.")
	c.flagSet.StringVar(&c.flagBaoAuthType, "bao-auth-type", agent.DefaultBaoAuthType,
		fmt.Sprintf("Type of Openbao Auth Method to use. Defaults to %q.", agent.DefaultBaoAuthType))
	c.flagSet.StringVar(&c.flagBaoAuthPath, "bao-auth-path", agent.DefaultBaoAuthPath,
		fmt.Sprintf("Mount path of the Openbao Auth Method. Defaults to %q.", agent.DefaultBaoAuthPath))
	c.flagSet.StringVar(&c.flagBaoNamespace, "bao-namespace", "", "Openbao namespace.")
	c.flagSet.BoolVar(&c.flagRevokeOnShutdown, "revoke-on-shutdown", false,
		"Automatically revoke Openbao Token on Pod termination.")
	c.flagSet.StringVar(&c.flagRunAsUser, "run-as-user", strconv.Itoa(agent.DefaultAgentRunAsUser),
		fmt.Sprintf("User (uid) to run Openbao agent as. Defaults to %d.", agent.DefaultAgentRunAsUser))
	c.flagSet.StringVar(&c.flagRunAsGroup, "run-as-group", strconv.Itoa(agent.DefaultAgentRunAsGroup),
		fmt.Sprintf("Group (gid) to run Openbao agent as. Defaults to %d.", agent.DefaultAgentRunAsGroup))
	c.flagSet.BoolVar(&c.flagRunAsSameUser, "run-as-same-user", agent.DefaultAgentRunAsSameUser,
		"Run the injected Openbao agent containers as the User (uid) of the first application container in the pod. "+
			"Requires Spec.Containers[0].SecurityContext.RunAsUser to be set in the pod spec. "+
			"Defaults to false.")
	c.flagSet.BoolVar(&c.flagSetSecurityContext, "set-security-context", agent.DefaultAgentSetSecurityContext,
		fmt.Sprintf("Set SecurityContext in injected containers. Defaults to %v.", agent.DefaultAgentSetSecurityContext))
	c.flagSet.StringVar(&c.flagTelemetryPath, "telemetry-path", "",
		"Path under which to expose metrics")
	c.flagSet.BoolVar(&c.flagUseLeaderElector, "use-leader-elector", agent.DefaultAgentUseLeaderElector,
		"Use leader elector to coordinate multiple replicas when updating CA and Certs with auto-tls")
	c.flagSet.StringVar(&c.flagDefaultTemplate, "default-template", agent.DefaultTemplateType,
		"Sets the default template type (map or json). Defaults to map.")
	c.flagSet.StringVar(&c.flagResourceRequestCPU, "cpu-request", agent.DefaultResourceRequestCPU,
		fmt.Sprintf("CPU resource request set in injected containers. Defaults to %s", agent.DefaultResourceRequestCPU))
	c.flagSet.StringVar(&c.flagResourceRequestMem, "memory-request", agent.DefaultResourceRequestMem,
		fmt.Sprintf("Memory resource request set in injected containers. Defaults to %s", agent.DefaultResourceRequestMem))
	c.flagSet.StringVar(&c.flagResourceRequestEphemeral, "ephemeral-storage-request", "",
		"Ephemeral Storage resource request set in injected containers. Defaults to unset")

	c.flagSet.StringVar(&c.flagResourceLimitCPU, "cpu-limit", agent.DefaultResourceLimitCPU,
		fmt.Sprintf("CPU resource limit set in injected containers. Defaults to %s", agent.DefaultResourceLimitCPU))
	c.flagSet.StringVar(&c.flagResourceLimitMem, "memory-limit", agent.DefaultResourceLimitMem,
		fmt.Sprintf("Memory resource limit set in injected containers. Defaults to %s", agent.DefaultResourceLimitMem))
	c.flagSet.StringVar(&c.flagResourceLimitEphemeral, "ephemeral-storage-limit", "",
		"Ephemeral Storage resource limit set in injected containers. Defaults to unset")
	c.flagSet.StringVar(&c.flagAuthMinBackoff, "auth-min-backoff", "",
		"Sets the minimum backoff on auto-auth failure. Default is 1s")
	c.flagSet.StringVar(&c.flagAuthMaxBackoff, "auth-max-backoff", "",
		"Sets the maximum backoff on auto-auth failure. Default is 5m")
	c.flagSet.StringVar(&c.flagDisableIdleConnections, "disable-idle-connections", "",
		"Comma-separated list of Openbao features where idle connections should be disabled.")
	c.flagSet.StringVar(&c.flagDisableKeepAlives, "disable-keep-alives", "",
		"Comma-separated list of Openbao features where keep-alives should be disabled.")

	tlsVersions := []string{}
	for v := range tlsutil.TLSLookup {
		tlsVersions = append(tlsVersions, v)
	}
	sort.Strings(tlsVersions)
	tlsStr := strings.Join(tlsVersions, ", ")
	c.flagSet.StringVar(&c.flagTLSMinVersion, "tls-min-version", defaultTLSMinVersion,
		fmt.Sprintf(`Minimum supported version of TLS. Defaults to %s. Accepted values are %s.`, defaultTLSMinVersion, tlsStr))
	c.flagSet.StringVar(&c.flagTLSCipherSuites, "tls-cipher-suites", "",
		"Comma-separated list of supported cipher suites for TLS 1.0-1.2")

	c.help = flags.Usage(help, c.flagSet)
}

func (c *Command) logLevel() (hclog.Level, error) {
	var level hclog.Level
	c.flagLogLevel = strings.ToLower(strings.TrimSpace(c.flagLogLevel))

	switch c.flagLogLevel {
	case "trace":
		level = hclog.Trace
	case "debug":
		level = hclog.Debug
	case "notice", "info", "":
		level = hclog.Info
	case "warn", "warning":
		level = hclog.Warn
	case "err", "error":
		level = hclog.Error
	default:
		return level, fmt.Errorf("unknown log level: %s", c.flagLogLevel)
	}
	return level, nil
}

func (c *Command) parseEnvs() error {
	var envs Specification

	err := envconfig.Process("agent_inject", &envs)
	if err != nil {
		return err
	}

	if envs.Listen != "" {
		c.flagListen = envs.Listen
	}

	if envs.LogLevel != "" {
		c.flagLogLevel = envs.LogLevel
	}

	if envs.LogFormat != "" {
		c.flagLogFormat = envs.LogFormat
	}

	if envs.TemplateConfigExitOnRetryFailure != "" {
		c.flagExitOnRetryFailure, err = parseutil.ParseBool(envs.TemplateConfigExitOnRetryFailure)
		if err != nil {
			return err
		}
	}

	if envs.TemplateConfigStaticSecretRenderInterval != "" {
		c.flagStaticSecretRenderInterval = envs.TemplateConfigStaticSecretRenderInterval
	}

	if envs.TemplateConfigMaxConnectionsPerHost != "" {
		c.flagMaxConnectionsPerHost, err = parseutil.ParseInt(envs.TemplateConfigMaxConnectionsPerHost)
		if err != nil {
			return err
		}
	}

	if envs.TLSAuto != "" {
		c.flagAutoName = envs.TLSAuto
	}

	if envs.TLSAutoHosts != "" {
		c.flagAutoHosts = envs.TLSAutoHosts
	}

	if envs.TLSCertFile != "" {
		c.flagCertFile = envs.TLSCertFile
	}

	if envs.TLSKeyFile != "" {
		c.flagKeyFile = envs.TLSKeyFile
	}

	if v := ReadBaoVariable(EnvBaoImage); v != "" {
		c.flagBaoImage = v
	}

	if v := ReadBaoVariable(EnvBaoAddress); v != "" {
		c.flagBaoService = v
	}
	if v := ReadBaoVariable(EnvBaoCACertBytes); v != "" {
		c.flagBaoCACertBytes = v
	}

	if envs.ProxyAddr != "" {
		c.flagProxyAddress = envs.ProxyAddr
	}

	if v := ReadBaoVariable(EnvBaoAuthType); v != "" {
		c.flagBaoAuthType = v
	}

	if v := ReadBaoVariable(EnvBaoAuthPath); v != "" {
		c.flagBaoAuthPath = v
	}

	if v := ReadBaoVariable(EnvBaoNamespace); v != "" {
		c.flagBaoNamespace = v
	}

	if envs.RevokeOnShutdown != "" {
		c.flagRevokeOnShutdown, err = parseutil.ParseBool(envs.RevokeOnShutdown)
		if err != nil {
			return err
		}
	}

	if envs.RunAsUser != "" {
		c.flagRunAsUser = envs.RunAsUser
	}

	if envs.RunAsGroup != "" {
		c.flagRunAsGroup = envs.RunAsGroup
	}

	if envs.RunAsSameUser != "" {
		c.flagRunAsSameUser, err = parseutil.ParseBool(envs.RunAsSameUser)
		if err != nil {
			return err
		}
	}

	if envs.SetSecurityContext != "" {
		c.flagSetSecurityContext, err = parseutil.ParseBool(envs.SetSecurityContext)
		if err != nil {
			return err
		}
	}

	if envs.TelemetryPath != "" {
		c.flagTelemetryPath = envs.TelemetryPath
	}

	if envs.UseLeaderElector != "" {
		c.flagUseLeaderElector, err = parseutil.ParseBool(envs.UseLeaderElector)
		if err != nil {
			return err
		}
	}

	if envs.DefaultTemplate != "" {
		c.flagDefaultTemplate = envs.DefaultTemplate
	}

	if envs.ResourceRequestCPU != "" {
		c.flagResourceRequestCPU = envs.ResourceRequestCPU
	}

	if envs.ResourceRequestMem != "" {
		c.flagResourceRequestMem = envs.ResourceRequestMem
	}

	if envs.ResourceRequestEphemeral != "" {
		c.flagResourceRequestEphemeral = envs.ResourceRequestEphemeral
	}

	if envs.ResourceLimitCPU != "" {
		c.flagResourceLimitCPU = envs.ResourceLimitCPU
	}

	if envs.ResourceLimitMem != "" {
		c.flagResourceLimitMem = envs.ResourceLimitMem
	}

	if envs.ResourceLimitEphemeral != "" {
		c.flagResourceLimitEphemeral = envs.ResourceLimitEphemeral
	}

	if envs.TLSMinVersion != "" {
		c.flagTLSMinVersion = envs.TLSMinVersion
	}

	if envs.TLSCipherSuites != "" {
		c.flagTLSCipherSuites = envs.TLSCipherSuites
	}

	if envs.AuthMinBackoff != "" {
		c.flagAuthMinBackoff = envs.AuthMinBackoff
	}

	if c.flagAuthMinBackoff != "" {
		_, err = time.ParseDuration(c.flagAuthMinBackoff)
		if err != nil {
			return err
		}
	}

	if envs.AuthMaxBackoff != "" {
		c.flagAuthMaxBackoff = envs.AuthMaxBackoff
	}

	if c.flagAuthMaxBackoff != "" {
		_, err = time.ParseDuration(c.flagAuthMaxBackoff)
		if err != nil {
			return err
		}
	}

	if envs.DisableIdleConnections != "" {
		c.flagDisableIdleConnections = envs.DisableIdleConnections
	}

	if envs.DisableKeepAlives != "" {
		c.flagDisableKeepAlives = envs.DisableKeepAlives
	}

	return nil
}
