# OpenBao + Kubernetes (openbao-k8s)

**Please note**: We take OpenBao's security and our users' trust very seriously. If you believe you have found a security issue in OpenBao, _please responsibly disclose_ by contacting us at [openbao-security@lists.lfedge.org](openbao-security@lists.lfedge.org).

----

The `openbao-k8s` binary includes first-class integrations between OpenBao and Kubernetes.  Currently the only integration in this repository is the OpenBao Agent Sidecar Injector (`agent-inject`).  In the future more integrations will be found here.

This project is versioned separately from OpenBao. Supported OpenBao versions for each feature will be noted below. By versioning this project separately, we can iterate on Kubernetes integrations more quickly and release new versions without forcing OpenBao users to do a full OpenBao upgrade.

## Features

  * [**Agent Inject**](https://openbao.org/docs/platform/k8s/injector/index.html):
    Agent Inject is a mutation webhook controller that injects OpenBao Agent containers into pods meeting specific annotation criteria. _(Requires OpenBao 2+)_

## Installation

`openbao-k8s` is distributed in multiple forms:

  * The recommended installation method is the official [OpenBao Helm chart](https://github.com/openbao/openbao-helm). This will automatically configure openbao and Kubernetes integration to run within an existing Kubernetes cluster.

  * A Docker image [`openbao/openbao-k8s`](https://hub.docker.com/r/openbao/openbao-k8s) is in the works. This can be used to manually run `openbao-k8s` within a scheduled environment.

  * Raw binaries are available on the [releases page](https://github.com/openbao/openbao-k8s/releases). These can be used to run openbao-k8s directly or build custom packages.
