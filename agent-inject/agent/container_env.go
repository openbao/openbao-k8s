// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"encoding/base64"
	"strconv"

	corev1 "k8s.io/api/core/v1"
)

var baseContainerEnvVars []corev1.EnvVar = []corev1.EnvVar{
	corev1.EnvVar{
		Name: "NAMESPACE",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "metadata.namespace",
			},
		},
	},
	corev1.EnvVar{
		Name: "HOST_IP",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "status.hostIP",
			},
		},
	},
	corev1.EnvVar{
		Name: "POD_IP",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "status.podIP",
			},
		},
	},
}

// ContainerEnvVars adds the applicable environment vars
// for the Openbao Agent sidecar.
func (a *Agent) ContainerEnvVars(init bool) ([]corev1.EnvVar, error) {
	envs := baseContainerEnvVars

	if a.Openbao.GoMaxProcs != "" {
		envs = append(envs, corev1.EnvVar{
			Name:  "GOMAXPROCS",
			Value: a.Openbao.GoMaxProcs,
		})
	}

	if a.Openbao.ClientTimeout != "" {
		envs = append(envs, corev1.EnvVar{
			Name:  "OPENBAO_CLIENT_TIMEOUT",
			Value: a.Openbao.ClientTimeout,
		})
	}

	if a.Openbao.ClientMaxRetries != "" {
		envs = append(envs, corev1.EnvVar{
			Name:  "OPENBAO_MAX_RETRIES",
			Value: a.Openbao.ClientMaxRetries,
		})
	}

	if a.Openbao.LogLevel != "" {
		envs = append(envs, corev1.EnvVar{
			Name:  "OPENBAO_LOG_LEVEL",
			Value: a.Openbao.LogLevel,
		})
	}

	if a.Openbao.LogFormat != "" {
		envs = append(envs, corev1.EnvVar{
			Name:  "OPENBAO_LOG_FORMAT",
			Value: a.Openbao.LogFormat,
		})
	}

	if a.Openbao.ProxyAddress != "" {
		envs = append(envs, corev1.EnvVar{
			Name:  "HTTPS_PROXY",
			Value: a.Openbao.ProxyAddress,
		})
	}

	if a.ConfigMapName == "" {
		config, err := a.newConfig(init)
		if err != nil {
			return envs, err
		}

		b64Config := base64.StdEncoding.EncodeToString(config)
		envs = append(envs, corev1.EnvVar{
			Name:  "OPENBAO_CONFIG",
			Value: b64Config,
		})
	} else {
		// set up environment variables to access Openbao since "openbao" section may not be present in the config
		if a.Openbao.Address != "" {
			envs = append(envs, corev1.EnvVar{
				Name:  "OPENBAO_ADDR",
				Value: a.Openbao.Address,
			})
		}
		if a.Openbao.CACert != "" {
			envs = append(envs, corev1.EnvVar{
				Name:  "OPENBAO_CACERT",
				Value: a.Openbao.CACert,
			})
		}
		if a.Openbao.CAKey != "" {
			envs = append(envs, corev1.EnvVar{
				Name:  "OPENBAO_CAPATH",
				Value: a.Openbao.CAKey,
			})
		}
		if a.Openbao.ClientCert != "" {
			envs = append(envs, corev1.EnvVar{
				Name:  "OPENBAO_CLIENT_CERT",
				Value: a.Openbao.ClientCert,
			})
		}
		if a.Openbao.ClientKey != "" {
			envs = append(envs, corev1.EnvVar{
				Name:  "OPENBAO_CLIENT_KEY",
				Value: a.Openbao.ClientKey,
			})
		}
		envs = append(envs, corev1.EnvVar{
			Name:  "OPENBAO_SKIP_VERIFY",
			Value: strconv.FormatBool(a.Openbao.TLSSkipVerify),
		})
		if a.Openbao.TLSServerName != "" {
			envs = append(envs, corev1.EnvVar{
				Name:  "OPENBAO_TLS_SERVER_NAME",
				Value: a.Openbao.TLSServerName,
			})
		}
	}

	if a.Openbao.CACertBytes != "" {
		envs = append(envs, corev1.EnvVar{
			Name:  "OPENBAO_CACERT_BYTES",
			Value: decodeIfBase64(a.Openbao.CACertBytes),
		})
	}

	// Add IRSA AWS Env variables for openbao containers
	if a.Openbao.AuthType == "aws" {
		envMap := a.getAwsEnvsFromContainer(a.Pod)
		for k, v := range envMap {
			envs = append(envs, corev1.EnvVar{
				Name:  k,
				Value: v,
			})
		}
		if a.Openbao.AuthConfig["region"] != nil {
			if r, ok := a.Openbao.AuthConfig["region"].(string); ok {
				envs = append(envs, corev1.EnvVar{
					Name:  "AWS_REGION",
					Value: r,
				})
			}
		}
	}

	return envs, nil
}

func decodeIfBase64(s string) string {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return string(decoded)
	}

	return s
}
