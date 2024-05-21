// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
)

const (
	// AnnotationAgentStatus is the key of the annotation that is added to
	// a pod after an injection is done.
	// There's only one valid status we care about: "injected".
	AnnotationAgentStatus = "openbao.openbao.org/agent-inject-status"

	// AnnotationAgentInject is the key of the annotation that controls whether
	// injection is explicitly enabled or disabled for a pod. This should
	// be set to a true or false value, as parseable by parseutil.ParseBool
	AnnotationAgentInject = "openbao.openbao.org/agent-inject"

	// AnnotationAgentInjectSecret is the key annotation that configures Openbao
	// Agent to retrieve the secrets from Openbao required by the app.  The name
	// of the secret is any unique string after "openbao.openbao.org/agent-inject-secret-",
	// such as "openbao.openbao.org/agent-inject-secret-foobar".  The value is the
	// path in Openbao where the secret is located.
	AnnotationAgentInjectSecret = "openbao.openbao.org/agent-inject-secret"

	// AnnotationAgentInjectFile is the key of the annotation that contains the
	// name (and optional path) of the file to create on disk. The name of the
	// secret is the string after "openbao.openbao.org/agent-inject-file-", and
	// should map to the same unique value provided in
	// "openbao.openbao.org/agent-inject-secret-". The value is the filename and
	// path in the secrets volume where the openbao secret will be written. The
	// container mount path of the secrets volume may be modified with the
	// secret-volume-path annotation.
	AnnotationAgentInjectFile = "openbao.openbao.org/agent-inject-file"

	// AnnotationAgentInjectFilePermission is the key of the annotation that contains the
	// permission of the file to create on disk. The name of the
	// secret is the string after "openbao.openbao.org/agent-inject-perms-", and
	// should map to the same unique value provided in
	// "openbao.openbao.org/agent-inject-secret-". The value is the value of the permission, for
	// example "0644"
	AnnotationAgentInjectFilePermission = "openbao.openbao.org/agent-inject-perms"

	// AnnotationAgentInjectTemplate is the key annotation that configures Openbao
	// Agent what template to use for rendering the secrets.  The name
	// of the template is any unique string after "openbao.openbao.org/agent-inject-template-",
	// such as "openbao.openbao.org/agent-inject-template-foobar".  This should map
	// to the same unique value provided in "openbao.openbao.org/agent-inject-secret-".
	// If not provided, a default generic template is used.
	AnnotationAgentInjectTemplate = "openbao.openbao.org/agent-inject-template"

	// AnnotationAgentInjectContainers is the key of the annotation that controls
	// in which containers the secrets volume should be mounted. Multiple containers can
	// be specified in a comma-separated list. If not provided, the secrets volume will
	// be mounted in all containers in the pod.
	AnnotationAgentInjectContainers = "openbao.openbao.org/agent-inject-containers"

	// AnnotationAgentInjectDefaultTemplate sets the default template type. Possible values
	// are "json" and "map".
	AnnotationAgentInjectDefaultTemplate = "openbao.openbao.org/agent-inject-default-template"

	// AnnotationAgentInjectTemplateFile is the optional key annotation that configures Openbao
	// Agent what template on disk to use for rendering the secrets.  The name
	// of the template is any unique string after "openbao.openbao.org/agent-inject-template-file-",
	// such as "openbao.openbao.org/agent-inject-template-file-foobar".  This should map
	// to the same unique value provided in "openbao.openbao.org/agent-inject-secret-".
	// The value is the filename and path of the template used by the agent to render the secrets.
	// If not provided, the template content key annotation is used.
	AnnotationAgentInjectTemplateFile = "openbao.openbao.org/agent-inject-template-file"

	// AnnotationAgentInjectToken is the annotation key for injecting the
	// auto-auth token into the secrets volume (e.g. /openbao/secrets/token)
	AnnotationAgentInjectToken = "openbao.openbao.org/agent-inject-token"

	// AnnotationAgentInjectCommand is the key annotation that configures Openbao Agent
	// to run a command after the secret is rendered. The name of the template is any
	// unique string after "openbao.openbao.org/agent-inject-command-". This should map
	// to the same unique value provided in "openbao.openbao.org/agent-inject-secret-".
	// If not provided (the default), no command is executed.
	AnnotationAgentInjectCommand = "openbao.openbao.org/agent-inject-command"

	// AnnotationAgentImage is the name of the Openbao docker image to use.
	AnnotationAgentImage = "openbao.openbao.org/agent-image"

	// AnnotationAgentRequestNamespace is the Kubernetes namespace where the request
	// originated from.
	AnnotationAgentRequestNamespace = "openbao.openbao.org/agent-request-namespace"

	// AnnotationAgentInitFirst makes the initialization container the first container
	// to run when a pod starts. Default is last.
	AnnotationAgentInitFirst = "openbao.openbao.org/agent-init-first"

	// AnnotationAgentPrePopulate controls whether an init container is included
	// to pre-populate the shared memory volume with secrets prior to the application
	// starting.
	AnnotationAgentPrePopulate = "openbao.openbao.org/agent-pre-populate"

	// AnnotationAgentPrePopulateOnly controls whether an init container is the only
	// injected container.  If true, no sidecar container will be injected at runtime
	// of the application.
	AnnotationAgentPrePopulateOnly = "openbao.openbao.org/agent-pre-populate-only"

	// AnnotationAgentConfigMap is the name of the configuration map where Openbao Agent
	// configuration file and templates can be found.
	AnnotationAgentConfigMap = "openbao.openbao.org/agent-configmap"

	// AnnotationAgentExtraSecret is the name of a Kubernetes secret that will be mounted
	// into the Openbao agent container so that the agent config can reference secrets.
	AnnotationAgentExtraSecret = "openbao.openbao.org/agent-extra-secret"
	// AnnotationAgentLimitsCPU sets the CPU limit on the Openbao Agent containers.
	AnnotationAgentLimitsCPU = "openbao.openbao.org/agent-limits-cpu"

	// AnnotationAgentLimitsMem sets the memory limit on the Openbao Agent containers.
	AnnotationAgentLimitsMem = "openbao.openbao.org/agent-limits-mem"

	// AnnotationAgentLimitsEphemeral sets the ephemeral storage limit on the Openbao Agent containers.
	AnnotationAgentLimitsEphemeral = "openbao.openbao.org/agent-limits-ephemeral"

	// AnnotationAgentRequestsCPU sets the requested CPU amount on the Openbao Agent containers.
	AnnotationAgentRequestsCPU = "openbao.openbao.org/agent-requests-cpu"

	// AnnotationAgentRequestsMem sets the requested memory amount on the Openbao Agent containers.
	AnnotationAgentRequestsMem = "openbao.openbao.org/agent-requests-mem"

	// AnnotationAgentRequestsEphemeral sets the ephemeral storage request on the Openbao Agent containers.
	AnnotationAgentRequestsEphemeral = "openbao.openbao.org/agent-requests-ephemeral"

	// AnnotationAgentRevokeOnShutdown controls whether a sidecar container will revoke its
	// own Openbao token before shutting down. If you are using a custom agent template, you must
	// make sure it's written to `/home/openbao/.openbao-token`. Only supported for sidecar containers.
	AnnotationAgentRevokeOnShutdown = "openbao.openbao.org/agent-revoke-on-shutdown"

	// AnnotationAgentRevokeGrace sets the number of seconds after receiving the signal for pod
	// termination that the container will attempt to revoke its own Openbao token. Defaults to 5s.
	AnnotationAgentRevokeGrace = "openbao.openbao.org/agent-revoke-grace"

	// AnnotationOpenbaoNamespace is the Openbao namespace where secrets can be found.
	AnnotationOpenbaoNamespace = "openbao.openbao.org/namespace"

	// AnnotationAgentRunAsUser sets the User ID to run the Openbao Agent containers as.
	AnnotationAgentRunAsUser = "openbao.openbao.org/agent-run-as-user"

	// AnnotationAgentRunAsGroup sets the Group ID to run the Openbao Agent containers as.
	AnnotationAgentRunAsGroup = "openbao.openbao.org/agent-run-as-group"

	// AnnotationAgentRunAsSameUser sets the User ID of the injected Openbao Agent
	// containers to the User ID of the first application container in the Pod.
	// Requires Spec.Containers[0].SecurityContext.RunAsUser to be set in the
	// Pod Spec.
	AnnotationAgentRunAsSameUser = "openbao.openbao.org/agent-run-as-same-user"

	// AnnotationAgentShareProcessNamespace sets the shareProcessNamespace value on the pod spec.
	AnnotationAgentShareProcessNamespace = "openbao.openbao.org/agent-share-process-namespace"

	// AnnotationAgentSetSecurityContext controls whether a SecurityContext (uid
	// and gid) is set on the injected Openbao Agent containers
	AnnotationAgentSetSecurityContext = "openbao.openbao.org/agent-set-security-context"

	// AnnotationAgentServiceAccountTokenVolumeName is the optional name of a volume containing a
	// service account token
	AnnotationAgentServiceAccountTokenVolumeName = "openbao.openbao.org/agent-service-account-token-volume-name"

	// AnnotationOpenbaoService is the name of the Openbao server.  This can be overridden by the
	// user but will be set by a flag on the deployment.
	AnnotationOpenbaoService = "openbao.openbao.org/service"

	// AnnotationProxyAddress is the HTTP proxy to use when talking to the Openbao server.
	AnnotationProxyAddress = "openbao.openbao.org/proxy-address"

	// AnnotationOpenbaoTLSSkipVerify allows users to configure verifying TLS
	// when communicating with Openbao.
	AnnotationOpenbaoTLSSkipVerify = "openbao.openbao.org/tls-skip-verify"

	// AnnotationOpenbaoTLSSecret is the name of the Kubernetes secret containing
	// client TLS certificates and keys.
	AnnotationOpenbaoTLSSecret = "openbao.openbao.org/tls-secret"

	// AnnotationOpenbaoTLSServerName is the name of the Openbao server to verify the
	// authenticity of the server when communicating with Openbao over TLS.
	AnnotationOpenbaoTLSServerName = "openbao.openbao.org/tls-server-name"

	// AnnotationOpenbaoCACert is the path of the CA certificate used to verify Openbao's
	// CA certificate.
	AnnotationOpenbaoCACert = "openbao.openbao.org/ca-cert"

	// AnnotationOpenbaoCAKey is the path of the CA key used to verify Openbao's CA.
	AnnotationOpenbaoCAKey = "openbao.openbao.org/ca-key"

	// AnnotationOpenbaoClientCert is the path of the client certificate used to communicate
	// with Openbao over TLS.
	AnnotationOpenbaoClientCert = "openbao.openbao.org/client-cert"

	// AnnotationOpenbaoClientKey is the path of the client key used to communicate
	// with Openbao over TLS.
	AnnotationOpenbaoClientKey = "openbao.openbao.org/client-key"

	// AnnotationOpenbaoClientMaxRetries is the number of retry attempts when 5xx errors are encountered.
	AnnotationOpenbaoClientMaxRetries = "openbao.openbao.org/client-max-retries"

	// AnnotationOpenbaoClientTimeout sets the request timeout when communicating with Openbao.
	AnnotationOpenbaoClientTimeout = "openbao.openbao.org/client-timeout"

	// AnnotationOpenbaoGoMaxProcs sets the Openbao Agent go max procs.
	AnnotationOpenbaoGoMaxProcs = "openbao.openbao.org/go-max-procs"

	// AnnotationOpenbaoLogLevel sets the Openbao Agent log level.
	AnnotationOpenbaoLogLevel = "openbao.openbao.org/log-level"

	// AnnotationOpenbaoLogFormat sets the Openbao Agent log format.
	AnnotationOpenbaoLogFormat = "openbao.openbao.org/log-format"

	// AnnotationOpenbaoRole specifies the role to be used for the Kubernetes auto-auth
	// method.
	AnnotationOpenbaoRole = "openbao.openbao.org/role"

	// AnnotationOpenbaoAuthType specifies the auto-auth method type to be used.
	AnnotationOpenbaoAuthType = "openbao.openbao.org/auth-type"

	// AnnotationOpenbaoAuthPath specifies the mount path to be used for the auto-auth method.
	AnnotationOpenbaoAuthPath = "openbao.openbao.org/auth-path"

	// AnnotationOpenbaoAuthConfig specifies the Auto Auth Method configuration parameters.
	// The name of the parameter is any unique string after "openbao.openbao.org/auth-config-",
	// such as "openbao.openbao.org/auth-config-foobar".
	AnnotationOpenbaoAuthConfig = "openbao.openbao.org/auth-config"

	// AnnotationOpenbaoSecretVolumePath specifies where the secrets are to be
	// Mounted after fetching.
	AnnotationOpenbaoSecretVolumePath = "openbao.openbao.org/secret-volume-path"

	// AnnotationPreserveSecretCase if enabled will preserve the case of secret name
	// by default the name is converted to lower case.
	AnnotationPreserveSecretCase = "openbao.openbao.org/preserve-secret-case"

	// AnnotationAgentCacheEnable if enabled will configure the sidecar container
	// to enable agent caching
	AnnotationAgentCacheEnable = "openbao.openbao.org/agent-cache-enable"

	// AnnotationAgentCacheUseAutoAuthToken configures the agent cache to use the
	// auto auth token or not. Can be set to "force" to force usage of the auto-auth token
	AnnotationAgentCacheUseAutoAuthToken = "openbao.openbao.org/agent-cache-use-auto-auth-token"

	// AnnotationAgentCacheListenerPort configures the port the agent cache should listen on
	AnnotationAgentCacheListenerPort = "openbao.openbao.org/agent-cache-listener-port"

	// AnnotationAgentCacheExitOnErr configures whether the agent will exit on an
	// error while restoring the persistent cache
	AnnotationAgentCacheExitOnErr = "openbao.openbao.org/agent-cache-exit-on-err"

	// AnnotationAgentCopyVolumeMounts is the name of the container or init container
	// in the Pod whose volume mounts should be copied onto the Openbao Agent init and
	// sidecar containers. Ignores any Kubernetes service account token mounts.
	AnnotationAgentCopyVolumeMounts = "openbao.openbao.org/agent-copy-volume-mounts"

	// AnnotationTemplateConfigExitOnRetryFailure configures whether agent
	// will exit on template render failures once it has exhausted all its retry
	// attempts. Defaults to true.
	AnnotationTemplateConfigExitOnRetryFailure = "openbao.openbao.org/template-config-exit-on-retry-failure"

	// AnnotationTemplateConfigStaticSecretRenderInterval
	// If specified, configures how often Openbao Agent Template should render non-leased secrets such as KV v2.
	// Defaults to 5 minutes.
	AnnotationTemplateConfigStaticSecretRenderInterval = "openbao.openbao.org/template-static-secret-render-interval"

	// AnnotationTemplateConfigMaxConnectionsPerHost limits the total number of connections
	//  that the Openbao Agent templating engine can use for a particular Openbao host. This limit
	//  includes connections in the dialing, active, and idle states.
	AnnotationTemplateConfigMaxConnectionsPerHost = "openbao.openbao.org/template-max-connections-per-host"

	// AnnotationAgentEnableQuit configures whether the quit endpoint is
	// enabled in the injected agent config
	AnnotationAgentEnableQuit = "openbao.openbao.org/agent-enable-quit"

	// AnnotationAgentAuthMinBackoff specifies the minimum backoff duration used when the agent auto auth fails.
	// Defaults to 1 second.
	AnnotationAgentAuthMinBackoff = "openbao.openbao.org/auth-min-backoff"

	// AnnotationAgentAuthMaxBackoff specifies the maximum backoff duration used when the agent auto auth fails.
	// Defaults to 5 minutes.
	AnnotationAgentAuthMaxBackoff = "openbao.openbao.org/auth-max-backoff"

	// AnnotationAgentDisableIdleConnections specifies disabling idle connections for various
	// features in Openbao Agent. Comma-separated string, with valid values auto-auth, caching,
	// templating.
	AnnotationAgentDisableIdleConnections = "openbao.openbao.org/agent-disable-idle-connections"

	// AnnotationAgentDisableKeepAlives specifies disabling keep-alives for various
	// features in Openbao Agent. Comma-separated string, with valid values auto-auth, caching,
	// templating.
	AnnotationAgentDisableKeepAlives = "openbao.openbao.org/agent-disable-keep-alives"

	// AnnotationAgentJsonPatch is used to specify a JSON patch to be applied to the agent sidecar container before
	// it is created.
	AnnotationAgentJsonPatch = "openbao.openbao.org/agent-json-patch"

	// AnnotationAgentInitJsonPatch is used to specify a JSON patch to be applied to the agent init container before
	// it is created.
	AnnotationAgentInitJsonPatch = "openbao.openbao.org/agent-init-json-patch"

	// AnnotationAgentAutoAuthExitOnError is used to control if a failure in the auto_auth method will cause the agent to exit or try indefinitely (the default).
	AnnotationAgentAutoAuthExitOnError = "openbao.openbao.org/agent-auto-auth-exit-on-err"

	// AnnotationAgentTelemetryConfig specifies the Agent Telemetry configuration parameters.
	// The name of the parameter is any unique string after "openbao.openbao.org/agent-telemetry-",
	// such as "openbao.openbao.org/agent-telemetry-foobar".
	AnnotationAgentTelemetryConfig = "openbao.openbao.org/agent-telemetry"

	// AnnotationErrorOnMissingKey is the key of annotation that configures whether
	// template should error when a key is missing in the secret. The name of the
	// secret is the string after "openbao.openbao.org/error-on-missing-key-", and
	// should map to the same unique value provided in
	// "openbao.openbao.org/agent-inject-secret-". Defaults to false
	AnnotationErrorOnMissingKey = "openbao.openbao.org/error-on-missing-key"
)

type AgentConfig struct {
	Image                      string
	Address                    string
	AuthType                   string
	AuthPath                   string
	OpenbaoNamespace             string
	Namespace                  string
	RevokeOnShutdown           bool
	UserID                     string
	GroupID                    string
	SameID                     bool
	SetSecurityContext         bool
	ShareProcessNamespace      bool
	ProxyAddress               string
	DefaultTemplate            string
	ResourceRequestCPU         string
	ResourceRequestMem         string
	ResourceRequestEphemeral   string
	ResourceLimitCPU           string
	ResourceLimitMem           string
	ResourceLimitEphemeral     string
	ExitOnRetryFailure         bool
	StaticSecretRenderInterval string
	MaxConnectionsPerHost      int64
	AuthMinBackoff             string
	AuthMaxBackoff             string
	DisableIdleConnections     string
	DisableKeepAlives          string
}

// Init configures the expected annotations required to create a new instance
// of Agent.  This should be run before running new to ensure all annotations are
// present.
func Init(pod *corev1.Pod, cfg AgentConfig) error {
	var securityContextIsSet bool
	var runAsUserIsSet bool
	var runAsSameUserIsSet bool
	var runAsGroupIsSet bool

	if pod == nil {
		return errors.New("pod is empty")
	}

	if cfg.Address == "" {
		return errors.New("address for Openbao required")
	}

	if cfg.AuthPath == "" {
		return errors.New("Openbao Auth Path required")
	}

	if cfg.Namespace == "" {
		return errors.New("kubernetes namespace required")
	}

	if pod.ObjectMeta.Annotations == nil {
		pod.ObjectMeta.Annotations = make(map[string]string)
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationOpenbaoService]; !ok {
		pod.ObjectMeta.Annotations[AnnotationOpenbaoService] = cfg.Address
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationOpenbaoAuthType]; !ok {
		if cfg.AuthType == "" {
			cfg.AuthType = DefaultOpenbaoAuthType
		}
		pod.ObjectMeta.Annotations[AnnotationOpenbaoAuthType] = cfg.AuthType
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationOpenbaoAuthPath]; !ok {
		pod.ObjectMeta.Annotations[AnnotationOpenbaoAuthPath] = cfg.AuthPath
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationOpenbaoNamespace]; !ok {
		pod.ObjectMeta.Annotations[AnnotationOpenbaoNamespace] = cfg.OpenbaoNamespace
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationProxyAddress]; !ok {
		pod.ObjectMeta.Annotations[AnnotationProxyAddress] = cfg.ProxyAddress
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentImage]; !ok {
		if cfg.Image == "" {
			cfg.Image = DefaultOpenbaoImage
		}
		pod.ObjectMeta.Annotations[AnnotationAgentImage] = cfg.Image
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentRequestNamespace]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentRequestNamespace] = cfg.Namespace
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentLimitsCPU]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentLimitsCPU] = cfg.ResourceLimitCPU
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentLimitsMem]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentLimitsMem] = cfg.ResourceLimitMem
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentLimitsEphemeral]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentLimitsEphemeral] = cfg.ResourceLimitEphemeral
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentRequestsCPU]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentRequestsCPU] = cfg.ResourceRequestCPU
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentRequestsMem]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentRequestsMem] = cfg.ResourceRequestMem
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentRequestsEphemeral]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentRequestsEphemeral] = cfg.ResourceRequestEphemeral
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationOpenbaoSecretVolumePath]; !ok {
		pod.ObjectMeta.Annotations[AnnotationOpenbaoSecretVolumePath] = secretVolumePath
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentRevokeOnShutdown]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentRevokeOnShutdown] = strconv.FormatBool(cfg.RevokeOnShutdown)
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentRevokeGrace]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentRevokeGrace] = strconv.Itoa(DefaultRevokeGrace)
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationOpenbaoLogLevel]; !ok {
		pod.ObjectMeta.Annotations[AnnotationOpenbaoLogLevel] = DefaultAgentLogLevel
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationOpenbaoLogFormat]; !ok {
		pod.ObjectMeta.Annotations[AnnotationOpenbaoLogFormat] = DefaultAgentLogFormat
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentServiceAccountTokenVolumeName]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentServiceAccountTokenVolumeName] = ""
	}

	if _, securityContextIsSet = pod.ObjectMeta.Annotations[AnnotationAgentSetSecurityContext]; !securityContextIsSet {
		pod.ObjectMeta.Annotations[AnnotationAgentSetSecurityContext] = strconv.FormatBool(cfg.SetSecurityContext)
	}

	if _, runAsUserIsSet = pod.ObjectMeta.Annotations[AnnotationAgentRunAsUser]; !runAsUserIsSet {

		if cfg.UserID == "" {
			cfg.UserID = strconv.Itoa(DefaultAgentRunAsUser)
		}
		pod.ObjectMeta.Annotations[AnnotationAgentRunAsUser] = cfg.UserID
	}

	if _, runAsSameUserIsSet = pod.ObjectMeta.Annotations[AnnotationAgentRunAsSameUser]; !runAsSameUserIsSet {
		pod.ObjectMeta.Annotations[AnnotationAgentRunAsSameUser] = strconv.FormatBool(cfg.SameID)
	}

	if _, runAsGroupIsSet = pod.ObjectMeta.Annotations[AnnotationAgentRunAsGroup]; !runAsGroupIsSet {
		if cfg.GroupID == "" {
			cfg.GroupID = strconv.Itoa(DefaultAgentRunAsGroup)
		}
		pod.ObjectMeta.Annotations[AnnotationAgentRunAsGroup] = cfg.GroupID
	}

	// If the SetSecurityContext startup option is false, and the analogous
	// annotation isn't set, but one of the user or group annotations is set,
	// flip SetSecurityContext to true so that the user and group options are
	// set in the containers.
	if !cfg.SetSecurityContext && !securityContextIsSet && (runAsUserIsSet || runAsSameUserIsSet || runAsGroupIsSet) {
		pod.ObjectMeta.Annotations[AnnotationAgentSetSecurityContext] = strconv.FormatBool(true)
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentCacheEnable]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentCacheEnable] = DefaultAgentCacheEnable
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentCacheListenerPort]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentCacheListenerPort] = DefaultAgentCacheListenerPort
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentCacheUseAutoAuthToken]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentCacheUseAutoAuthToken] = DefaultAgentCacheUseAutoAuthToken
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentCacheExitOnErr]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentCacheExitOnErr] = strconv.FormatBool(DefaultAgentCacheExitOnErr)
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentInjectContainers]; !ok {
		containerNames := make([]string, len(pod.Spec.Containers))
		for i, v := range pod.Spec.Containers {
			containerNames[i] = v.Name
		}
		pod.ObjectMeta.Annotations[AnnotationAgentInjectContainers] = strings.Join(containerNames, ",")
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentInjectDefaultTemplate]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentInjectDefaultTemplate] = cfg.DefaultTemplate
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationTemplateConfigExitOnRetryFailure]; !ok {
		pod.ObjectMeta.Annotations[AnnotationTemplateConfigExitOnRetryFailure] = strconv.FormatBool(cfg.ExitOnRetryFailure)
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationTemplateConfigStaticSecretRenderInterval]; !ok {
		pod.ObjectMeta.Annotations[AnnotationTemplateConfigStaticSecretRenderInterval] = cfg.StaticSecretRenderInterval
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationTemplateConfigMaxConnectionsPerHost]; !ok {
		pod.ObjectMeta.Annotations[AnnotationTemplateConfigMaxConnectionsPerHost] = strconv.FormatInt(cfg.MaxConnectionsPerHost, 10)
	}

	if minBackoffString, ok := pod.ObjectMeta.Annotations[AnnotationAgentAuthMinBackoff]; ok {
		if minBackoffString != "" {
			_, err := time.ParseDuration(minBackoffString)
			if err != nil {
				return fmt.Errorf("error parsing min backoff as duration: %v", err)
			}
		}
	} else if cfg.AuthMinBackoff != "" {
		// set default from env/flag
		pod.ObjectMeta.Annotations[AnnotationAgentAuthMinBackoff] = cfg.AuthMinBackoff
	}

	if maxBackoffString, ok := pod.ObjectMeta.Annotations[AnnotationAgentAuthMaxBackoff]; ok {
		if maxBackoffString != "" {
			_, err := time.ParseDuration(maxBackoffString)
			if err != nil {
				return fmt.Errorf("error parsing max backoff as duration: %v", err)
			}
		}
	} else if cfg.AuthMaxBackoff != "" {
		// set default from env/flag
		pod.ObjectMeta.Annotations[AnnotationAgentAuthMaxBackoff] = cfg.AuthMaxBackoff
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentDisableIdleConnections]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentDisableIdleConnections] = cfg.DisableIdleConnections
	}

	if _, ok := pod.ObjectMeta.Annotations[AnnotationAgentDisableKeepAlives]; !ok {
		pod.ObjectMeta.Annotations[AnnotationAgentDisableKeepAlives] = cfg.DisableKeepAlives
	}

	// validate JSON patches
	if patch, ok := pod.ObjectMeta.Annotations[AnnotationAgentJsonPatch]; ok {
		// ignore empty string
		if patch == "" {
			delete(pod.ObjectMeta.Annotations, AnnotationAgentJsonPatch)
		} else {
			_, err := jsonpatch.DecodePatch([]byte(patch))
			if err != nil {
				return fmt.Errorf("error parsing JSON patch for annotation %s: %w", AnnotationAgentJsonPatch, err)
			}
		}
	}
	if patch, ok := pod.ObjectMeta.Annotations[AnnotationAgentInitJsonPatch]; ok {
		// ignore empty string
		if patch == "" {
			delete(pod.ObjectMeta.Annotations, AnnotationAgentInitJsonPatch)
		} else {
			_, err := jsonpatch.DecodePatch([]byte(patch))
			if err != nil {
				return fmt.Errorf("error parsing JSON patch for annotation %s: %w", AnnotationAgentInitJsonPatch, err)
			}
		}
	}

	return nil
}

// secrets parses annotations with the pattern "openbao.openbao.org/agent-inject-secret-".
// Everything following the final dash becomes the name of the secret, and the
// value is the path in Openbao. This method also matches and returns the
// Template, Command, and FilePathAndName settings from annotations associated
// with a secret name.
//
// For example: "openbao.openbao.org/agent-inject-secret-foobar: db/creds/foobar"
// Name: foobar, Path: db/creds/foobar
func (a *Agent) secrets() ([]*Secret, error) {
	var (
		secrets     []*Secret
		secretNames = make(map[string]struct{})
	)
	secretAnnotations := []string{AnnotationAgentInjectSecret, AnnotationAgentInjectTemplateFile, AnnotationAgentInjectTemplate}
	for annotationName, annotationValue := range a.Annotations {
		if strings.TrimSpace(annotationValue) == "" {
			continue
		}

		for _, annotation := range secretAnnotations {
			rawName, ok := strings.CutPrefix(annotationName, annotation+"-")
			if !ok {
				continue
			}

			secretName, ok := a.secretName(rawName)
			if !ok {
				continue
			}

			if _, ok := secretNames[rawName]; ok {
				break
			}

			secretNames[rawName] = struct{}{}
			secrets = append(secrets, &Secret{Name: secretName, RawName: rawName})

			break
		}

	}

	for _, secret := range secrets {
		secret.Path = a.annotationsSecretValue(AnnotationAgentInjectSecret, secret.RawName, "")
		secret.Template = a.annotationsSecretValue(AnnotationAgentInjectTemplate, secret.RawName, "")
		if secret.Template == "" {
			secret.TemplateFile = a.annotationsSecretValue(AnnotationAgentInjectTemplateFile, secret.RawName, secret.TemplateFile)
		}
		secret.MountPath = a.annotationsSecretValue(AnnotationOpenbaoSecretVolumePath, secret.RawName, a.Annotations[AnnotationOpenbaoSecretVolumePath])
		secret.Command = a.annotationsSecretValue(AnnotationAgentInjectCommand, secret.RawName, "")
		secret.FilePathAndName = a.annotationsSecretValue(AnnotationAgentInjectFile, secret.RawName, "")
		secret.FilePermission = a.annotationsSecretValue(AnnotationAgentInjectFilePermission, secret.RawName, "")

		errMissingKey, err := parseutil.ParseBool(
			a.annotationsSecretValue(AnnotationErrorOnMissingKey, secret.RawName, ""),
		)
		if err != nil {
			return nil, err
		}
		secret.ErrMissingKey = errMissingKey
	}

	return secrets, nil
}

func (a *Agent) annotationsSecretValue(annotation, rawSecretName, defaultValue string) string {
	if val, ok := a.Annotations[fmt.Sprintf("%s-%s", annotation, rawSecretName)]; ok {
		return val
	}

	return defaultValue
}

func (a *Agent) secretName(raw string) (name string, notEmpty bool) {
	name = raw
	if ok, _ := a.preserveSecretCase(raw); !ok {
		name = strings.ToLower(raw)
	}

	if name == "" {
		return "", false
	}

	return name, true
}

func (a *Agent) inject() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentInject]
	if !ok {
		return true, nil
	}

	return parseutil.ParseBool(raw)
}

func (a *Agent) initFirst() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentInitFirst]
	if !ok {
		return false, nil
	}

	return parseutil.ParseBool(raw)
}

func (a *Agent) prePopulate() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentPrePopulate]
	if !ok {
		return true, nil
	}

	return parseutil.ParseBool(raw)
}

func (a *Agent) prePopulateOnly() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentPrePopulateOnly]
	if !ok {
		return false, nil
	}

	return parseutil.ParseBool(raw)
}

func (a *Agent) revokeOnShutdown() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentRevokeOnShutdown]
	if !ok {
		return false, nil
	}

	return parseutil.ParseBool(raw)
}

func (a *Agent) revokeGrace() (uint64, error) {
	raw, ok := a.Annotations[AnnotationAgentRevokeGrace]
	if !ok {
		return 0, nil
	}

	return strconv.ParseUint(raw, 10, 64)
}

func (a *Agent) tlsSkipVerify() (bool, error) {
	raw, ok := a.Annotations[AnnotationOpenbaoTLSSkipVerify]
	if !ok {
		return false, nil
	}

	return parseutil.ParseBool(raw)
}

func (a *Agent) preserveSecretCase(secretName string) (bool, error) {
	preserveSecretCaseAnnotationName := fmt.Sprintf("%s-%s", AnnotationPreserveSecretCase, secretName)

	var raw string

	if val, ok := a.Annotations[preserveSecretCaseAnnotationName]; ok {
		raw = val
	} else {
		raw, ok = a.Annotations[AnnotationPreserveSecretCase]
		if !ok {
			return false, nil
		}
	}
	return parseutil.ParseBool(raw)
}

func (a *Agent) runAsSameID(pod *corev1.Pod) (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentRunAsSameUser]
	if !ok {
		return DefaultAgentRunAsSameUser, nil
	}
	runAsSameID, err := parseutil.ParseBool(raw)
	if err != nil {
		return DefaultAgentRunAsSameUser, err
	}
	if runAsSameID {
		if len(pod.Spec.Containers) == 0 {
			return DefaultAgentRunAsSameUser, errors.New("No containers found in Pod Spec")
		}
		if pod.Spec.Containers[0].SecurityContext == nil {
			return DefaultAgentRunAsSameUser, errors.New("No SecurityContext found for Container 0")
		}
		if pod.Spec.Containers[0].SecurityContext.RunAsUser == nil {
			return DefaultAgentRunAsSameUser, errors.New("RunAsUser is nil for Container 0's SecurityContext")
		}
		if *pod.Spec.Containers[0].SecurityContext.RunAsUser == 0 {
			return DefaultAgentRunAsSameUser, errors.New("container not allowed to run as root")
		}
		a.RunAsUser = *pod.Spec.Containers[0].SecurityContext.RunAsUser
	}
	return runAsSameID, nil
}

// returns value, ok, error
func (a *Agent) setShareProcessNamespace(pod *corev1.Pod) (bool, bool, error) {
	annotation := AnnotationAgentShareProcessNamespace
	raw, ok := a.Annotations[annotation]
	if !ok {
		return false, false, nil
	}
	shareProcessNamespace, err := parseutil.ParseBool(raw)
	if err != nil {
		return false, true, fmt.Errorf(
			"invalid value %v for annotation %q, err=%w", raw, annotation, err)
	}
	if pod.Spec.ShareProcessNamespace != nil {
		if !*pod.Spec.ShareProcessNamespace && shareProcessNamespace {
			return false, true,
				errors.New("shareProcessNamespace explicitly disabled on the pod, " +
					"refusing to enable it")
		}
	}

	return shareProcessNamespace, true, nil
}

func (a *Agent) setSecurityContext() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentSetSecurityContext]
	if !ok {
		return DefaultAgentSetSecurityContext, nil
	}

	return parseutil.ParseBool(raw)
}

func (a *Agent) cacheEnable() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentCacheEnable]
	if !ok {
		return false, nil
	}

	return parseutil.ParseBool(raw)
}

func (a *Agent) templateConfigExitOnRetryFailure() (bool, error) {
	raw, ok := a.Annotations[AnnotationTemplateConfigExitOnRetryFailure]
	if !ok {
		return DefaultTemplateConfigExitOnRetryFailure, nil
	}

	return parseutil.ParseBool(raw)
}

func (a *Agent) templateConfigMaxConnectionsPerHost() (int64, error) {
	raw, ok := a.Annotations[AnnotationTemplateConfigMaxConnectionsPerHost]
	if !ok {
		return 0, nil
	}

	return parseutil.ParseInt(raw)
}

func (a *Agent) getAutoAuthExitOnError() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentAutoAuthExitOnError]
	if !ok {
		return DefaultAutoAuthEnableOnExit, nil
	}

	return parseutil.ParseBool(raw)
}

func (a *Agent) getEnableQuit() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentEnableQuit]
	if !ok {
		return DefaultEnableQuit, nil
	}
	return parseutil.ParseBool(raw)
}

func (a *Agent) cachePersist(cacheEnabled bool) bool {
	if cacheEnabled && a.PrePopulate && !a.PrePopulateOnly {
		return true
	}
	return false
}

func (a *Agent) cacheExitOnErr() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentCacheExitOnErr]
	if !ok {
		return false, nil
	}

	return parseutil.ParseBool(raw)
}

func (a *Agent) injectToken() (bool, error) {
	raw, ok := a.Annotations[AnnotationAgentInjectToken]
	if !ok {
		return DefaultAgentInjectToken, nil
	}
	return parseutil.ParseBool(raw)
}

// telemetryConfig accumulates the agent-telemetry annotations into a map which is
// later rendered into the telemetry{} stanza of the Openbao Agent config.
func (a *Agent) telemetryConfig() map[string]interface{} {
	telemetryConfig := make(map[string]interface{})

	prefix := fmt.Sprintf("%s-", AnnotationAgentTelemetryConfig)
	for annotation, value := range a.Annotations {
		if strings.HasPrefix(annotation, prefix) {
			param := strings.TrimPrefix(annotation, prefix)
			param = strings.ReplaceAll(param, "-", "_")
			var v interface{}
			if err := json.Unmarshal([]byte(value), &v); err != nil {
				v = value
			}
			telemetryConfig[param] = v
		}
	}
	return telemetryConfig
}

func (a *Agent) authConfig() map[string]interface{} {
	authConfig := make(map[string]interface{})

	// set token_path parameter from the Agent prior to assignment from annotations
	// so that annotations can override the value assigned in agent.go https://github.com/hashicorp/vault-k8s/issues/456
	if a.ServiceAccountTokenVolume.MountPath != "" && a.ServiceAccountTokenVolume.TokenPath != "" {
		authConfig["token_path"] = path.Join(a.ServiceAccountTokenVolume.MountPath, a.ServiceAccountTokenVolume.TokenPath)
	}

	// set authConfig parameters from annotations
	prefix := fmt.Sprintf("%s-", AnnotationOpenbaoAuthConfig)
	for annotation, value := range a.Annotations {
		if strings.HasPrefix(annotation, prefix) {
			param := strings.TrimPrefix(annotation, prefix)
			param = strings.ReplaceAll(param, "-", "_")
			authConfig[param] = value
		}
	}

	if a.Openbao.Role != "" {
		authConfig["role"] = a.Openbao.Role
	}

	return authConfig
}
