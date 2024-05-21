// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"testing"

	"github.com/openbao/openbao/sdk/helper/strutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var baseEnvVars = []string{"NAMESPACE", "HOST_IP", "POD_IP"}

func TestContainerEnvs(t *testing.T) {

	tests := []struct {
		agent        Agent
		expectedEnvs []string
	}{
		{Agent{}, append(baseEnvVars, "OPENBAO_CONFIG")},
		{Agent{Openbao: Openbao{Address: "http://localhost:8200"}, ConfigMapName: "foobar"}, append(baseEnvVars, "OPENBAO_SKIP_VERIFY", "OPENBAO_ADDR")},
		{Agent{Openbao: Openbao{ClientMaxRetries: "0"}}, append(baseEnvVars, "OPENBAO_CONFIG", "OPENBAO_MAX_RETRIES")},
		{Agent{Openbao: Openbao{ClientTimeout: "5s"}}, append(baseEnvVars, "OPENBAO_CONFIG", "OPENBAO_CLIENT_TIMEOUT")},
		{Agent{Openbao: Openbao{ClientMaxRetries: "0", ClientTimeout: "5s"}}, append(baseEnvVars, "OPENBAO_CONFIG", "OPENBAO_MAX_RETRIES", "OPENBAO_CLIENT_TIMEOUT")},
		{Agent{ConfigMapName: "foobar", Openbao: Openbao{Address: "http://localhost:8200", ClientMaxRetries: "0", ClientTimeout: "5s", LogLevel: "info", ProxyAddress: "http://proxy:3128"}}, append(baseEnvVars, "OPENBAO_MAX_RETRIES", "OPENBAO_CLIENT_TIMEOUT", "OPENBAO_LOG_LEVEL", "HTTPS_PROXY", "OPENBAO_SKIP_VERIFY", "OPENBAO_ADDR")},
		{Agent{Openbao: Openbao{GoMaxProcs: "1"}}, append(baseEnvVars, "OPENBAO_CONFIG", "GOMAXPROCS")},
	}

	for _, tt := range tests {
		envs, err := tt.agent.ContainerEnvVars(true)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}
		if len(envs) != len(tt.expectedEnvs) {
			t.Errorf("number of envs mismatch, wanted %d, got %d", len(tt.expectedEnvs), len(envs))
		}

		for _, env := range envs {
			if !strutil.StrListContains(tt.expectedEnvs, env.Name) {
				t.Errorf("unexpected env found %s", env.Name)
			}
		}
	}
}

func TestContainerEnvsForIRSA(t *testing.T) {
	envTests := []struct {
		agent        Agent
		expectedEnvs []string
	}{
		{Agent{Pod: testPodWithoutIRSA()}, append(baseEnvVars, "OPENBAO_CONFIG")},
		{Agent{Pod: testPodWithIRSA(), Openbao: Openbao{AuthType: "aws"}},
			append(baseEnvVars, "OPENBAO_CONFIG", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_DEFAULT_REGION", "AWS_REGION"),
		},
	}
	for _, tt := range envTests {
		envs, err := tt.agent.ContainerEnvVars(true)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}
		if len(envs) != len(tt.expectedEnvs) {
			t.Errorf("number of envs mismatch, wanted %d, got %d", len(tt.expectedEnvs), len(envs))
		}
	}
}

func TestAwsRegionEnvForAwsAuthMethod(t *testing.T) {
	input := []struct {
		agent        Agent
		expectedEnvs []string
	}{
		{Agent{Pod: testPodWithRegionInAuthConfig(), Openbao: Openbao{AuthType: "aws", AuthConfig: getRegionMap()}},
			append(baseEnvVars, "OPENBAO_CONFIG", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_REGION"),
		},
		{Agent{Pod: testPodWithIRSA(), Openbao: Openbao{AuthType: "aws"}},
			append(baseEnvVars, "OPENBAO_CONFIG", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_DEFAULT_REGION", "AWS_REGION"),
		},
	}
	for _, item := range input {
		envs, err := item.agent.ContainerEnvVars(true)
		if err != nil {
			t.Errorf("got error, shouldn't have: %s", err)
		}
		if len(envs) != len(item.expectedEnvs) {
			t.Errorf("number of envs mismatch, wanted %d, got %d", len(item.expectedEnvs), len(envs))
		}
	}
}

func getRegionMap() map[string]interface{} {
	return map[string]interface{}{
		"region": "us-gov-east-1",
	}
}

func testPodWithoutIRSA() *corev1.Pod {
	return testPodWithEnv(nil)
}

func testPodWithIRSA() *corev1.Pod {
	return testPodWithEnv([]corev1.EnvVar{
		{
			Name:  "AWS_ROLE_ARN",
			Value: "foorole",
		},
		{
			Name:  "AWS_WEB_IDENTITY_TOKEN_FILE",
			Value: "footoken",
		},
		{
			Name:  "AWS_DEFAULT_REGION",
			Value: "default-region",
		},
		{
			Name:  "AWS_REGION",
			Value: "test-region",
		},
	})
}

func testPodWithRegionInAuthConfig() *corev1.Pod {
	return testPodWithEnv([]corev1.EnvVar{
		{
			Name:  "AWS_ROLE_ARN",
			Value: "foorole",
		},
		{
			Name:  "AWS_WEB_IDENTITY_TOKEN_FILE",
			Value: "footoken",
		},
	})
}

func testPodWithEnv(envVars []corev1.EnvVar) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "foobar",
					Env:  envVars,
				},
			},
		},
	}
}
