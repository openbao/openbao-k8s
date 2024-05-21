// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/openbao/openbao/sdk/helper/strutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/pointer"
)

const (
	DefaultOpenbaoImage                       = "openbao/openbao:1.16.1"
	DefaultOpenbaoAuthType                    = "kubernetes"
	DefaultOpenbaoAuthPath                    = "auth/kubernetes"
	DefaultAgentRunAsUser                   = 100
	DefaultAgentRunAsGroup                  = 1000
	DefaultAgentRunAsSameUser               = false
	DefaultAgentAllowPrivilegeEscalation    = false
	DefaultAgentDropCapabilities            = "ALL"
	DefaultAgentSetSecurityContext          = true
	DefaultAgentReadOnlyRoot                = true
	DefaultAgentCacheEnable                 = "false"
	DefaultAgentCacheUseAutoAuthToken       = "true"
	DefaultAgentCacheListenerPort           = "8200"
	DefaultAgentCacheExitOnErr              = false
	DefaultAgentUseLeaderElector            = false
	DefaultAgentInjectToken                 = false
	DefaultTemplateConfigExitOnRetryFailure = true
	DefaultServiceAccountMount              = "/var/run/secrets/openbao.openbao.org/serviceaccount"
	DefaultEnableQuit                       = false
	DefaultAutoAuthEnableOnExit             = false
)

// Agent is the top level structure holding all the
// configurations for the Openbao Agent container.
type Agent struct {
	// Annotations are the current pod annotations used to
	// configure the Openbao Agent container.
	Annotations map[string]string

	// DefaultTemplate is the default template to be used when
	// no custom template is specified via annotations.
	DefaultTemplate string

	// ImageName is the name of the Openbao image to use for the
	// sidecar container.
	ImageName string

	// Containers determine which containers should be injected
	Containers []string

	// Inject is the flag used to determine if a container should be requested
	// in a pod request.
	Inject bool

	// InitFirst controls whether an init container is first to run.
	InitFirst bool

	// LimitsCPU is the upper CPU limit the sidecar container is allowed to consume.
	LimitsCPU string

	// LimitsMem is the upper memory limit the sidecar container is allowed to consume.
	LimitsMem string

	// LimitsEphemeral is the upper ephemeral storage limit the sidecar container is allowed to consume.
	LimitsEphemeral string

	// Namespace is the Kubernetes namespace the request originated from.
	Namespace string

	// Pod is the original Kubernetes pod spec.
	Pod *corev1.Pod

	// PrePopulate controls whether an init container is added to the request.
	PrePopulate bool

	// PrePopulateOnly controls whether an init container is the _only_ container
	// added to the request.
	PrePopulateOnly bool

	// RevokeOnShutdown controls whether a sidecar container will attempt to revoke its Openbao
	// token on shutting down.
	RevokeOnShutdown bool

	// RevokeGrace controls after receiving the signal for pod
	// termination that the container will attempt to revoke its own Openbao token.
	RevokeGrace uint64

	// RequestsCPU is the requested minimum CPU amount required  when being scheduled to deploy.
	RequestsCPU string

	// RequestsMem is the requested minimum memory amount required when being scheduled to deploy.
	RequestsMem string

	// RequestsEphemeral is the requested minimum ephemeral storage amount required when being scheduled to deploy.
	RequestsEphemeral string

	// Secrets are all the templates, the path in Openbao where the secret can be
	// found, and the unique name of the secret which will be used for the filename.
	Secrets []*Secret

	// ServiceAccountTokenVolume holds details of a volume mount for a
	// Kubernetes service account token for the pod. This is used when we mount
	// the service account to the Openbao Agent container(s).
	ServiceAccountTokenVolume *ServiceAccountTokenVolume

	// Status is the current injection status.  The only status considered is "injected",
	// which prevents further mutations.  A user can patch this annotation to force a new
	// mutation.
	Status string

	// ConfigMapName is the name of the configmap a user wants to mount to Openbao Agent
	// container(s).
	ConfigMapName string

	// Openbao is the structure holding all the Openbao specific configurations.
	Openbao Openbao

	// OpenbaoAgentCache is the structure holding the Openbao agent cache specific configurations
	OpenbaoAgentCache OpenbaoAgentCache

	// OpenbaoAgentTemplateConfig is the structure holding the Openbao agent
	// template_config specific configuration
	OpenbaoAgentTemplateConfig OpenbaoAgentTemplateConfig

	// RunAsUser is the user ID to run the Openbao agent container(s) as.
	RunAsUser int64

	// RunAsGroup is the group ID to run the Openbao agent container(s) as.
	RunAsGroup int64

	// RunAsSameID sets the user ID of the Openbao agent container(s) to be the
	// same as the first application container
	RunAsSameID bool

	// ShareProcessNamespace sets the shareProcessNamespace value on the pod spec.
	ShareProcessNamespace *bool

	// SetSecurityContext controls whether the injected containers have a
	// SecurityContext set.
	SetSecurityContext bool

	// ExtraSecret is the Kubernetes secret to mount as a volume in the Openbao agent container
	// which can be referenced by the Agent config for secrets. Mounted at /openbao/custom/
	ExtraSecret string

	// AwsIamTokenAccountName is the aws iam volume mount name for the pod.
	// Need this for IRSA aka pod identity
	AwsIamTokenAccountName string

	// AwsIamTokenAccountPath is the aws iam volume mount path for the pod
	// where the JWT would be present
	// Need this for IRSA aka pod identity
	AwsIamTokenAccountPath string

	// CopyVolumeMounts is the name of the container in the Pod whose volume mounts
	// should be copied into the Openbao Agent init and/or sidecar containers.
	CopyVolumeMounts string

	// InjectToken controls whether the auto-auth token is injected into the
	// secrets volume (e.g. /openbao/secrets/token)
	InjectToken bool

	// EnableQuit controls whether the quit endpoint is enabled on a localhost
	// listener
	EnableQuit bool

	// DisableIdleConnections controls which Agent features have idle
	// connections disabled
	DisableIdleConnections []string

	// DisableKeepAlives controls which Agent features have keep-alives disabled.
	DisableKeepAlives []string

	// JsonPatch can be used to modify the agent sidecar container before it is created.
	JsonPatch string

	// InitJsonPatch can be used to modify the agent-init container before it is created.
	InitJsonPatch string

	// AutoAuthExitOnError is used to control if a failure in the auto_auth method will cause the agent to exit or try indefinitely (the default).
	AutoAuthExitOnError bool
}

type ServiceAccountTokenVolume struct {
	// Name of the volume
	Name string

	// MountPath of the volume within openbao agent containers
	MountPath string

	// TokenPath to the JWT token within the volume
	TokenPath string
}

type Secret struct {
	// Name of the secret used to identify other annotation directives, and used
	// as the filename for the rendered secret file (unless FilePathAndName is
	// specified).
	Name string

	// RawName is original annotation suffix value
	RawName string

	// Path in Openbao where the secret desired can be found.
	Path string

	// Template is the optional custom template to use when rendering the secret.
	Template string

	// Template file is the optional path on disk to the custom template to use when rendering the secret.
	TemplateFile string

	// Mount Path for the volume holding the rendered secret file
	MountPath string

	// Command is the optional command to run after rendering the secret.
	Command string

	// FilePathAndName is the optional file path and name for the rendered secret file.
	FilePathAndName string

	// FilePermission is the optional file permission for the rendered secret file
	FilePermission string

	// ErrMissingKey is used to control how the template behaves when attempting
	// to index a struct or a map key that does not exist
	ErrMissingKey bool
}

type Openbao struct {
	// Address is the Openbao service address.
	Address string

	// ProxyAddress is the proxy service address to use when talking to the Openbao service.
	ProxyAddress string

	// AuthType is type of Openbao Auth Method to use.
	AuthType string

	// AuthPath is the Mount Path of Openbao Auth Method.
	AuthPath string

	// AuthConfig is the Auto Auth Method configuration.
	AuthConfig map[string]interface{}

	// CACert is the name of the Certificate Authority certificate
	// to use when validating Openbao's server certificates. It takes
	// precedence over CACertBytes.
	CACert string

	// CACertBytes is the contents of the CA certificate to trust
	// for TLS with Openbao as a PEM-encoded certificate or bundle.
	// Can also be base64 encoded PEM contents.
	CACertBytes string

	// CAKey is the name of the Certificate Authority key
	// to use when validating Openbao's server certificates.
	CAKey string

	// ClientCert is the name of the client certificate to use when communicating
	// with Openbao over TLS.
	ClientCert string

	// ClientKey is the name of the client key to use when communicating
	// with Openbao over TLS.
	ClientKey string

	// ClientMaxRetries configures the number of retries the client should make
	// when 5-- errors are received from the Openbao server.  Default is 2.
	ClientMaxRetries string

	// ClientTimeout is the max number in seconds the client should attempt to
	// make a request to the Openbao server.
	ClientTimeout string

	// GoMaxProcs sets the Openbao Agent go max procs.
	GoMaxProcs string

	// LogLevel sets the Openbao Agent log level.  Defaults to info.
	LogLevel string

	// LogFormat sets the Openbao Agent log format.  Defaults to standard.
	LogFormat string

	// Namespace is the Openbao namespace to prepend to secret paths.
	Namespace string

	// Role is the name of the Openbao role to use for authentication.
	Role string

	// TLSSecret is the name of the secret to be mounted to the Openbao Agent container
	// containing the TLS certificates required to communicate with Openbao.
	TLSSecret string

	// TLSSkipVerify toggles verification of Openbao's certificates.
	TLSSkipVerify bool

	// TLSServerName is the name of the Openbao server to use when validating Openbao's
	// TLS certificates.
	TLSServerName string

	// AuthMinBackoff is the minimum time to backoff if auto auth fails.
	AuthMinBackoff string

	// AuthMinBackoff is the maximum time to backoff if auto auth fails.
	AuthMaxBackoff string

	// AgentTelemetryConfig is the agent telemetry configuration.
	AgentTelemetryConfig map[string]interface{}
}

type OpenbaoAgentCache struct {
	// Enable configures whether the cache is enabled or not
	Enable bool

	// ListenerPort is the port the cache should listen to
	ListenerPort string

	// UseAutoAuthToken configures whether the auto auth token is used in cache requests
	UseAutoAuthToken string

	// Persist marks whether persistent caching is enabled or not
	Persist bool

	// ExitOnErr configures whether the agent will exit on an error while
	// restoring the persistent cache
	ExitOnErr bool
}

type OpenbaoAgentTemplateConfig struct {
	// ExitOnRetryFailure configures whether agent should exit after failing
	// all its retry attempts when rendering templates
	ExitOnRetryFailure bool

	// StaticSecretRenderInterval If specified, configures how often
	// Openbao Agent Template should render non-leased secrets such as KV v2
	StaticSecretRenderInterval string

	// MaxConnectionsPerHost limits the total number of connections
	//  that the Openbao Agent templating engine can use for a particular Openbao host. This limit
	//  includes connections in the dialing, active, and idle states.
	MaxConnectionsPerHost int64
}

// New creates a new instance of Agent by parsing all the Kubernetes annotations.
func New(pod *corev1.Pod) (*Agent, error) {
	sa, err := serviceaccount(pod)
	if err != nil {
		return nil, err
	}
	var iamName, iamPath string
	if pod.Annotations[AnnotationOpenbaoAuthType] == "aws" {
		iamName, iamPath = getAwsIamTokenVolume(pod)
	}

	agent := &Agent{
		Annotations:               pod.Annotations,
		ConfigMapName:             pod.Annotations[AnnotationAgentConfigMap],
		ImageName:                 pod.Annotations[AnnotationAgentImage],
		DefaultTemplate:           pod.Annotations[AnnotationAgentInjectDefaultTemplate],
		LimitsCPU:                 pod.Annotations[AnnotationAgentLimitsCPU],
		LimitsMem:                 pod.Annotations[AnnotationAgentLimitsMem],
		LimitsEphemeral:           pod.Annotations[AnnotationAgentLimitsEphemeral],
		Namespace:                 pod.Annotations[AnnotationAgentRequestNamespace],
		Pod:                       pod,
		Containers:                []string{},
		RequestsCPU:               pod.Annotations[AnnotationAgentRequestsCPU],
		RequestsMem:               pod.Annotations[AnnotationAgentRequestsMem],
		RequestsEphemeral:         pod.Annotations[AnnotationAgentRequestsEphemeral],
		ServiceAccountTokenVolume: sa,
		Status:                    pod.Annotations[AnnotationAgentStatus],
		ExtraSecret:               pod.Annotations[AnnotationAgentExtraSecret],
		CopyVolumeMounts:          pod.Annotations[AnnotationAgentCopyVolumeMounts],
		AwsIamTokenAccountName:    iamName,
		AwsIamTokenAccountPath:    iamPath,
		JsonPatch:                 pod.Annotations[AnnotationAgentJsonPatch],
		InitJsonPatch:             pod.Annotations[AnnotationAgentInitJsonPatch],
		Openbao: Openbao{
			Address:          pod.Annotations[AnnotationOpenbaoService],
			ProxyAddress:     pod.Annotations[AnnotationProxyAddress],
			AuthType:         pod.Annotations[AnnotationOpenbaoAuthType],
			AuthPath:         pod.Annotations[AnnotationOpenbaoAuthPath],
			CACert:           pod.Annotations[AnnotationOpenbaoCACert],
			CAKey:            pod.Annotations[AnnotationOpenbaoCAKey],
			ClientCert:       pod.Annotations[AnnotationOpenbaoClientCert],
			ClientKey:        pod.Annotations[AnnotationOpenbaoClientKey],
			ClientMaxRetries: pod.Annotations[AnnotationOpenbaoClientMaxRetries],
			ClientTimeout:    pod.Annotations[AnnotationOpenbaoClientTimeout],
			GoMaxProcs:       pod.Annotations[AnnotationOpenbaoGoMaxProcs],
			LogLevel:         pod.Annotations[AnnotationOpenbaoLogLevel],
			LogFormat:        pod.Annotations[AnnotationOpenbaoLogFormat],
			Namespace:        pod.Annotations[AnnotationOpenbaoNamespace],
			Role:             pod.Annotations[AnnotationOpenbaoRole],
			TLSSecret:        pod.Annotations[AnnotationOpenbaoTLSSecret],
			TLSServerName:    pod.Annotations[AnnotationOpenbaoTLSServerName],
			AuthMinBackoff:   pod.Annotations[AnnotationAgentAuthMinBackoff],
			AuthMaxBackoff:   pod.Annotations[AnnotationAgentAuthMaxBackoff],
		},
	}

	agent.Secrets, err = agent.secrets()
	if err != nil {
		return agent, err
	}
	agent.Openbao.AuthConfig = agent.authConfig()
	agent.Inject, err = agent.inject()
	if err != nil {
		return agent, err
	}

	agent.Openbao.AgentTelemetryConfig = agent.telemetryConfig()

	agent.InitFirst, err = agent.initFirst()
	if err != nil {
		return agent, err
	}

	agent.PrePopulate, err = agent.prePopulate()
	if err != nil {
		return agent, err
	}

	agent.PrePopulateOnly, err = agent.prePopulateOnly()
	if err != nil {
		return agent, err
	}

	agent.RevokeOnShutdown, err = agent.revokeOnShutdown()
	if err != nil {
		return agent, err
	}

	agent.Containers = strings.Split(pod.Annotations[AnnotationAgentInjectContainers], ",")

	agent.RevokeGrace, err = agent.revokeGrace()
	if err != nil {
		return agent, err
	}

	agent.Openbao.TLSSkipVerify, err = agent.tlsSkipVerify()
	if err != nil {
		return agent, err
	}

	agent.RunAsUser, err = parseutil.ParseInt(pod.Annotations[AnnotationAgentRunAsUser])
	if err != nil {
		return agent, err
	}

	agent.RunAsGroup, err = parseutil.ParseInt(pod.Annotations[AnnotationAgentRunAsGroup])
	if err != nil {
		return agent, err
	}

	agent.RunAsSameID, err = agent.runAsSameID(pod)
	if err != nil {
		return agent, err
	}

	setShareProcessNamespace, ok, err := agent.setShareProcessNamespace(pod)
	if err != nil {
		return agent, err
	}
	if ok {
		agent.ShareProcessNamespace = pointer.Bool(setShareProcessNamespace)
	}

	agent.SetSecurityContext, err = agent.setSecurityContext()
	if err != nil {
		return agent, err
	}

	agentCacheEnable, err := agent.cacheEnable()
	if err != nil {
		return agent, err
	}

	agentCacheExitOnErr, err := agent.cacheExitOnErr()
	if err != nil {
		return agent, err
	}

	agent.DefaultTemplate = strings.ToLower(agent.DefaultTemplate)
	switch agent.DefaultTemplate {
	case "map":
	case "json":
	default:
		return agent, fmt.Errorf("invalid default template type: %s", agent.DefaultTemplate)
	}

	agent.InjectToken, err = agent.injectToken()
	if err != nil {
		return agent, err
	}

	agent.OpenbaoAgentCache = OpenbaoAgentCache{
		Enable:           agentCacheEnable,
		ListenerPort:     pod.Annotations[AnnotationAgentCacheListenerPort],
		UseAutoAuthToken: pod.Annotations[AnnotationAgentCacheUseAutoAuthToken],
		ExitOnErr:        agentCacheExitOnErr,
		Persist:          agent.cachePersist(agentCacheEnable),
	}

	exitOnRetryFailure, err := agent.templateConfigExitOnRetryFailure()
	if err != nil {
		return nil, err
	}

	maxConnectionsPerHost, err := agent.templateConfigMaxConnectionsPerHost()
	if err != nil {
		return nil, err
	}

	agent.OpenbaoAgentTemplateConfig = OpenbaoAgentTemplateConfig{
		ExitOnRetryFailure:         exitOnRetryFailure,
		StaticSecretRenderInterval: pod.Annotations[AnnotationTemplateConfigStaticSecretRenderInterval],
		MaxConnectionsPerHost:      maxConnectionsPerHost,
	}

	agent.EnableQuit, err = agent.getEnableQuit()
	if err != nil {
		return nil, err
	}

	if pod.Annotations[AnnotationAgentDisableIdleConnections] != "" {
		agent.DisableIdleConnections = strings.Split(pod.Annotations[AnnotationAgentDisableIdleConnections], ",")
	}

	if pod.Annotations[AnnotationAgentDisableKeepAlives] != "" {
		agent.DisableKeepAlives = strings.Split(pod.Annotations[AnnotationAgentDisableKeepAlives], ",")
	}

	agent.AutoAuthExitOnError, err = agent.getAutoAuthExitOnError()
	if err != nil {
		return nil, err
	}

	return agent, nil
}

// ShouldInject checks whether the pod in question should be injected
// with Openbao Agent containers.
func ShouldInject(pod *corev1.Pod) (bool, error) {
	raw, ok := pod.Annotations[AnnotationAgentInject]
	if !ok {
		return false, nil
	}

	inject, err := parseutil.ParseBool(raw)
	if err != nil {
		return false, err
	}

	if !inject {
		return false, nil
	}

	// If injection didn't happen on pod creation, then it's too late now.
	if pod.Status.Phase != "" && pod.Status.Phase != corev1.PodPending {
		return false, nil
	}

	// This shouldn't happen so bail.
	raw, ok = pod.Annotations[AnnotationAgentStatus]
	if !ok {
		return true, nil
	}

	// "injected" is the only status we care about.  Don't do
	// anything if it's set.  The user can update the status
	// to force a new mutation.
	if raw == "injected" {
		return false, nil
	}

	return true, nil
}

// Patch creates the necessary pod patches to inject the Openbao Agent
// containers.
func (a *Agent) Patch() ([]byte, error) {
	var patches jsonpatch.Patch
	// Add a volume for the token sink
	patches = append(patches, addVolumes(
		a.Pod.Spec.Volumes,
		a.ContainerTokenVolume(),
		"/spec/volumes")...)

	// Add our volume that will be shared by the containers
	// for passing data in the pod.
	patches = append(patches, addVolumes(
		a.Pod.Spec.Volumes,
		a.ContainerVolumes(),
		"/spec/volumes")...)

	// Add ConfigMap if one was provided
	if a.ConfigMapName != "" {
		patches = append(patches, addVolumes(
			a.Pod.Spec.Volumes,
			[]corev1.Volume{a.ContainerConfigMapVolume()},
			"/spec/volumes")...)
	}

	// Add ExtraSecret if one was provided
	if a.ExtraSecret != "" {
		patches = append(patches, addVolumes(
			a.Pod.Spec.Volumes,
			[]corev1.Volume{a.ContainerExtraSecretVolume()},
			"/spec/volumes")...)
	}

	// Add TLS Secret if one was provided
	if a.Openbao.TLSSecret != "" {
		patches = append(patches, addVolumes(
			a.Pod.Spec.Volumes,
			[]corev1.Volume{a.ContainerTLSSecretVolume()},
			"/spec/volumes")...)
	}

	// Add persistent cache volume if configured
	if a.OpenbaoAgentCache.Persist {
		patches = append(patches, addVolumes(
			a.Pod.Spec.Volumes,
			[]corev1.Volume{a.cacheVolume()},
			"/spec/volumes")...)
	}

	// Add Volume Mounts
	for i, container := range a.Pod.Spec.Containers {
		if strutil.StrListContains(a.Containers, container.Name) {
			patches = append(patches, addVolumeMounts(
				container.VolumeMounts,
				a.ContainerVolumeMounts(),
				fmt.Sprintf("/spec/containers/%d/volumeMounts", i))...)
		}
	}

	// Init Container
	if a.PrePopulate {
		container, err := a.ContainerInitSidecar()
		if err != nil {
			return nil, err
		}

		containers := a.Pod.Spec.InitContainers

		// Init Containers run sequentially in Kubernetes and sometimes the order in
		// which they run matters.  This reorders the init containers to put the agent first.
		// For example, if an init container needed Openbao secrets to work, the agent would need
		// to run first.
		if a.InitFirst {

			// Remove all init containers from the document, so we can re-add them after the agent.
			if len(a.Pod.Spec.InitContainers) != 0 {
				patches = append(patches, removeContainers("/spec/initContainers")...)
			}

			containers = []corev1.Container{container}
			containers = append(containers, a.Pod.Spec.InitContainers...)

			patches = append(patches, addContainers(
				[]corev1.Container{},
				containers,
				"/spec/initContainers")...)
		} else {
			patches = append(patches, addContainers(
				a.Pod.Spec.InitContainers,
				[]corev1.Container{container},
				"/spec/initContainers")...)
		}

		// Add Volume Mounts
		for i, container := range containers {
			if container.Name == "openbao-agent-init" {
				continue
			}
			patches = append(patches, addVolumeMounts(
				container.VolumeMounts,
				a.ContainerVolumeMounts(),
				fmt.Sprintf("/spec/initContainers/%d/volumeMounts", i))...)
		}

		// Add shareProcessNamespace
		if a.ShareProcessNamespace != nil {
			patches = append(patches, updateShareProcessNamespace(*a.ShareProcessNamespace)...)
		}
	}

	// Sidecar Container
	if !a.PrePopulateOnly {
		container, err := a.ContainerSidecar()
		if err != nil {
			return nil, err
		}
		patches = append(patches, addContainers(
			a.Pod.Spec.Containers,
			[]corev1.Container{container},
			"/spec/containers")...)
	}

	// Add annotations so that we know we're injected
	patches = append(patches, updateAnnotations(
		a.Pod.Annotations,
		map[string]string{AnnotationAgentStatus: "injected"})...)

	// Generate the patch
	if len(patches) > 0 {
		return json.Marshal(patches)
	}
	return nil, nil
}

// Validate the instance of Agent to ensure we have everything needed
// for basic functionality.
func (a *Agent) Validate() error {
	if a.Namespace == "" {
		return errors.New("namespace missing from request")
	}

	if a.ServiceAccountTokenVolume == nil ||
		a.ServiceAccountTokenVolume.Name == "" ||
		a.ServiceAccountTokenVolume.MountPath == "" ||
		a.ServiceAccountTokenVolume.TokenPath == "" {
		return errors.New("no service account token volume name, mount path or token path found")
	}

	if a.ImageName == "" {
		return errors.New("no Openbao image found")
	}

	if a.ConfigMapName == "" {
		if a.Openbao.AuthType == "" {
			return errors.New("no Openbao Auth Type found")
		}

		if a.Openbao.AuthType == DefaultOpenbaoAuthType &&
			a.Openbao.Role == "" && a.Annotations[fmt.Sprintf("%s-role", AnnotationOpenbaoAuthConfig)] == "" {
			return errors.New("no Openbao role found")
		}

		if a.Openbao.AuthPath == "" {
			return errors.New("no Openbao Auth Path found")
		}

		if a.Openbao.Address == "" {
			return errors.New("no Openbao address found")
		}
	}
	return nil
}

func serviceaccount(pod *corev1.Pod) (*ServiceAccountTokenVolume, error) {
	if volumeName := pod.ObjectMeta.Annotations[AnnotationAgentServiceAccountTokenVolumeName]; volumeName != "" {
		// Attempt to find existing mount point of named volume and copy mount path
		for _, container := range pod.Spec.Containers {
			for _, volumeMount := range container.VolumeMounts {
				if volumeMount.Name == volumeName {
					tokenPath, err := getProjectedTokenPath(pod, volumeName)
					if err != nil {
						return nil, err
					}
					return &ServiceAccountTokenVolume{
						Name:      volumeMount.Name,
						MountPath: volumeMount.MountPath,
						TokenPath: tokenPath,
					}, nil
				}
			}
		}

		// Otherwise, check the volume exists and fallback to `DefaultServiceAccountMount`
		for _, volume := range pod.Spec.Volumes {
			if volume.Name == volumeName {
				tokenPath, err := getTokenPathFromProjectedVolume(volume)
				if err != nil {
					return nil, err
				}
				return &ServiceAccountTokenVolume{
					Name:      volume.Name,
					MountPath: DefaultServiceAccountMount,
					TokenPath: tokenPath,
				}, nil
			}
		}

		return nil, fmt.Errorf("failed to find service account volume %q", volumeName)
	}

	// Fallback to searching for normal service account token
	for _, container := range pod.Spec.Containers {
		for _, volumes := range container.VolumeMounts {
			if strings.Contains(volumes.MountPath, "serviceaccount") {
				return &ServiceAccountTokenVolume{
					Name:      volumes.Name,
					MountPath: volumes.MountPath,
					TokenPath: "token",
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("failed to find service account volume mount")
}

// getProjectedTokenPath searches through a Pod's Volumes for volumeName, and
// attempts to retrieve the projected token path from that volume
func getProjectedTokenPath(pod *corev1.Pod, volumeName string) (string, error) {
	for _, volume := range pod.Spec.Volumes {
		if volume.Name == volumeName {
			return getTokenPathFromProjectedVolume(volume)
		}
	}
	return "", fmt.Errorf("failed to find volume %q in Pod %q volumes", volumeName, pod.Name)
}

func getTokenPathFromProjectedVolume(volume corev1.Volume) (string, error) {
	if volume.Projected != nil {
		for _, source := range volume.Projected.Sources {
			if source.ServiceAccountToken != nil && source.ServiceAccountToken.Path != "" {
				return source.ServiceAccountToken.Path, nil
			}
		}
	}
	return "", fmt.Errorf("failed to find tokenPath for projected volume %q", volume.Name)
}

// IRSA support - get aws_iam_token volume mount details to inject to openbao containers
func getAwsIamTokenVolume(pod *corev1.Pod) (string, string) {
	var awsIamTokenAccountName, awsIamTokenAccountPath string
	for _, container := range pod.Spec.Containers {
		for _, volumes := range container.VolumeMounts {
			if strings.Contains(volumes.MountPath, "eks.amazonaws.com") {
				return volumes.Name, volumes.MountPath
			}
		}
	}
	return awsIamTokenAccountName, awsIamTokenAccountPath
}

// IRSA support - get aws envs to inject to openbao containers
func (a *Agent) getAwsEnvsFromContainer(pod *corev1.Pod) map[string]string {
	envMap := make(map[string]string)
	for _, container := range pod.Spec.Containers {
		for _, env := range container.Env {
			if env.Name == "AWS_ROLE_ARN" || env.Name == "AWS_WEB_IDENTITY_TOKEN_FILE" || env.Name == "AWS_DEFAULT_REGION" || env.Name == "AWS_REGION" {
				if _, ok := envMap[env.Name]; !ok {
					envMap[env.Name] = env.Value
				}
			}
		}
	}
	return envMap
}

func (a *Agent) openbaoCliFlags() []string {
	flags := []string{
		fmt.Sprintf("-address=%s", a.Openbao.Address),
	}

	if a.Openbao.CACert != "" {
		flags = append(flags, fmt.Sprintf("-ca-cert=%s", a.Openbao.CACert))
	}

	if a.Openbao.ClientCert != "" {
		flags = append(flags, fmt.Sprintf("-client-cert=%s", a.Openbao.ClientCert))
	}

	if a.Openbao.ClientKey != "" {
		flags = append(flags, fmt.Sprintf("-client-key=%s", a.Openbao.ClientKey))
	}

	return flags
}

// copyVolumeMounts copies the specified container or init container's volume mounts.
// Ignores any Kubernetes service account token mounts.
func (a *Agent) copyVolumeMounts(targetContainerName string) []corev1.VolumeMount {
	// Deep copy the pod spec so append doesn't mutate the original containers slice
	podSpec := a.Pod.Spec.DeepCopy()
	copiedVolumeMounts := make([]corev1.VolumeMount, 0)
	for _, container := range append(podSpec.Containers, podSpec.InitContainers...) {
		if container.Name == targetContainerName {
			for _, volumeMount := range container.VolumeMounts {
				if !strings.Contains(strings.ToLower(volumeMount.MountPath), "serviceaccount") {
					copiedVolumeMounts = append(copiedVolumeMounts, volumeMount)
				}
			}
		}
	}
	return copiedVolumeMounts
}
