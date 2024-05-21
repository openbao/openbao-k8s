---
name: Bug report
about: Let us know about a bug!
title: ''
labels: bug
assignees: ''

---

<!-- Please reserve GitHub issues for bug reports and feature requests.

Please note: We take OpenBao's security and our users' trust very seriously. If you believe you have found a security issue in OpenBao, _please responsibly disclose_ by contacting us at openbao-security@lists.lfedge.org.

-->

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Deploy application annotated for openbao-agent injection
2. ...
4. See error (openbao injector logs, openbao-agent logs, etc.)

Application deployment:

```yaml
# Paste your application deployment yaml here.
# Be sure to scrub any sensitive values!
```

Other useful info to include: `kubectl describe deployment <app>` and `kubectl describe replicaset <app>` output.

**Expected behavior**
A clear and concise description of what you expected to happen.

**Environment**
* Kubernetes version:
  * Distribution or cloud vendor (OpenShift, EKS, GKE, AKS, etc.):
  * Other configuration options or runtime services (istio, etc.):
* openbao-k8s version:

**Additional context**
Add any other context about the problem here.
