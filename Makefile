REGISTRY_NAME ?= docker.io/openbao
IMAGE_NAME = openbao-k8s
VERSION ?= 0.0.0-dev
OPENBAO_VERSION ?= 1.16.1
IMAGE_TAG ?= $(REGISTRY_NAME)/$(IMAGE_NAME):$(VERSION)
PUBLISH_LOCATION ?= https://releases.hashicorp.com
DOCKER_DIR = ./build/docker
BUILD_DIR = dist
GOOS ?= linux
GOARCH ?= amd64
BIN_NAME = $(IMAGE_NAME)
GOFMT_FILES ?= $$(find . -name '*.go' | grep -v vendor)
XC_PUBLISH ?=
PKG = github.com/openbao/openbao-k8s/version
LDFLAGS ?= "-X '$(PKG).Version=v$(VERSION)'"
TESTARGS ?= '-test.v'

OPENBAO_HELM_CHART_VERSION ?= 0.27.0
# TODO: add support for testing against enterprise

TEST_WITHOUT_OPENBAO_TLS ?=
ifndef TEST_WITHOUT_OPENBAO_TLS
	OPENBAO_VERSION_PARTS := $(subst ., , $(OPENBAO_VERSION))
	OPENBAO_MAJOR_VERSION := $(word 1, $(OPENBAO_VERSION_PARTS))
	OPENBAO_MINOR_VERSION := $(word 2, $(OPENBAO_VERSION_PARTS))
	TEST_WITHOUT_OPENBAO_TLS := $(shell test $(OPENBAO_MAJOR_VERSION) -le 1 -a $(OPENBAO_MINOR_VERSION) -lt 15 && echo 1)
endif

HELM_VALUES_FILE ?= test/openbao/dev.values.yaml
ifdef TEST_WITHOUT_OPENBAO_TLS
	HELM_VALUES_FILE = test/openbao/dev-no-tls.values.yaml
endif

OPENBAO_HELM_DEFAULT_ARGS ?= --repo https://helm.releases.hashicorp.com --version=$(OPENBAO_HELM_CHART_VERSION) \
	--wait --timeout=5m \
	--values=$(HELM_VALUES_FILE) \
	--set server.image.tag=$(OPENBAO_VERSION) \
	--set injector.agentImage.tag=$(OPENBAO_VERSION) \
	--set 'injector.image.tag=$(VERSION)'

.PHONY: all test build image clean version deploy exercise teardown
all: build

version:
	@echo $(VERSION)

build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		-ldflags $(LDFLAGS) \
		-o $(BUILD_DIR)/$(BIN_NAME) \
		.

image: build
	docker build --build-arg VERSION=$(VERSION) --no-cache -t $(IMAGE_TAG) .

# Deploys Openbao dev server and a locally built Agent Injector.
# Run multiple times to deploy new builds of the injector.
OPENBAO_HELM_POST_INSTALL_ARGS ?=
ifndef TEST_WITHOUT_OPENBAO_TLS
	OPENBAO_HELM_POST_INSTALL_ARGS = "--set=injector.extraEnvironmentVars.AGENT_INJECT_OPENBAO_CACERT_BYTES=$$(kubectl exec openbao-0 -- sh -c 'cat /tmp/openbao-ca.pem | base64 -w0')"
endif
deploy:
	helm upgrade --install openbao openbao $(OPENBAO_HELM_DEFAULT_ARGS) \
		--set "injector.enabled=false"
	kubectl delete pod -l "app.kubernetes.io/instance=openbao"
	kubectl wait --for=condition=Ready --timeout=5m pod -l "app.kubernetes.io/instance=openbao"
	helm upgrade --install openbao openbao $(OPENBAO_HELM_DEFAULT_ARGS) $(OPENBAO_HELM_POST_INSTALL_ARGS)

# Populates the Openbao dev server with a secret, configures kubernetes auth, and
# deploys an nginx pod with annotations to have the secret injected.
exercise:
	kubectl exec openbao-0 -- bao kv put secret/test-app hello=world
	kubectl exec openbao-0 -- bao auth list -format json | jq -e  '."kubernetes/"' || kubectl exec openbao-0 -- bao auth enable kubernetes
	kubectl exec openbao-0 -- sh -c 'bao write auth/kubernetes/config kubernetes_host="https://$$KUBERNETES_PORT_443_TCP_ADDR:443"'
	echo 'path "secret/data/*" { capabilities = ["read"] }' | kubectl exec -i openbao-0 -- bao policy write test-app -
	kubectl exec openbao-0 -- bao write auth/kubernetes/role/test-app \
		bound_service_account_names=test-app-sa \
		bound_service_account_namespaces=default \
		policies=test-app
	kubectl create serviceaccount test-app-sa || true
	kubectl delete pod nginx --ignore-not-found
	kubectl run nginx \
		--image=nginx \
		--annotations="openbao.openbao.org/agent-inject=true" \
		--annotations="openbao.openbao.org/role=test-app" \
		--annotations="openbao.openbao.org/agent-inject-secret-secret.txt=secret/data/test-app" \
		--overrides='{ "apiVersion": "v1", "spec": { "serviceAccountName": "test-app-sa" } }'
	kubectl wait --for=condition=Ready --timeout=5m pod nginx
	kubectl exec nginx -c nginx -- cat /openbao/secrets/secret.txt

# Teardown any resources created in deploy and exercise targets.
teardown:
	helm uninstall --namespace default openbao --wait 2> /dev/null || true
	kubectl delete --ignore-not-found serviceaccount test-app-sa
	kubectl delete --ignore-not-found pod nginx

clean:
	-rm -rf $(BUILD_DIR)

test: unit-test

unit-test:
	go test -race $(TESTARGS) ./...

.PHONY: mod
mod:
	@go mod tidy

fmt:
	gofmt -w $(GOFMT_FILES)
