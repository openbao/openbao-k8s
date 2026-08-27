# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# This Dockerfile contains multiple targets.
# Use 'docker build --target=<name> .' to build one.
# e.g. `docker build --target=dev .`
#
# All non-dev targets have a VERSION argument that must be provided
# via --build-arg=VERSION=<version> when building.
# e.g. --build-arg VERSION=1.11.2
#
# `default` is the production docker image which cannot be built locally.
# For local dev and testing purposes, please build and use the `dev` docker image.
FROM scratch AS bin
ARG TARGETARCH
COPY --chmod=555 dist/${TARGETARCH}/openbao-k8s /bin/openbao-k8s

# This is {docker.io,quay.io,ghcr.io}/openbao/openbao-k8s.
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS default

COPY LICENSE /licenses/mozilla.txt

# Create a non-root user to run the software.
RUN addgroup openbao && \
    adduser -S -G openbao openbao

# Set up certificates, base tools, and software.
RUN set -eux && \
    apk update && \
    apk add --no-cache ca-certificates libcap su-exec iputils

# Copy the binary stage.
COPY --from=bin . /

# 8080/tcp is the webhook endpoint used by the OpenBao agent injector
EXPOSE 8080

USER openbao
ENTRYPOINT ["/bin/openbao-k8s"]


# This is {docker.io,quay.io,ghcr.io}/openbao/openbao-k8s-ubi.
FROM registry.access.redhat.com/ubi10-minimal:10.2@sha256:1e429ea364534f7baf494bac5cc54996b9b9d300f1da90e7b1dfa0ce455bfe39 AS ubi

COPY LICENSE /licenses/mozilla.txt

# Overwrite Red Hat-specific labels present on the UBI base image.
LABEL io.k8s.description="OpenBao K8s includes first-class integrations between OpenBao and Kuberentes. Integrations include the OpenBao Agent Injector mutating admission webhook" \
      io.k8s.display-name="OpenBao K8s" \
      io.openshift.expose-services="8080/tcp:https"

# Set up certificates and base tools.
RUN set -eux && \
    microdnf install -y ca-certificates gnupg openssl tzdata wget unzip procps shadow-utils

# Create a non-root user to run the software.
# On OpenShift, this will not matter since the container
# is run as a random user and group.
# This is just kept for consistency with our other images.
RUN groupadd --gid 1000 openbao && \
    adduser --uid 100 --system -g openbao openbao && \
    usermod -a -G root openbao

# Copy the binary stage.
COPY --from=bin . /

# 8080/tcp is the webhook endpoint used by the OpenBao agent injector
EXPOSE 8080

USER openbao
ENTRYPOINT ["/bin/openbao-k8s"]
