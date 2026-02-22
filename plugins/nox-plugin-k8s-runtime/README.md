# nox-plugin-k8s-runtime

**Inspect running Kubernetes workloads for security misconfigurations.**

<!-- badges -->
![Track: Dynamic Runtime](https://img.shields.io/badge/track-Dynamic%20Runtime-orange)
![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-00ADD8)

---

## Overview

`nox-plugin-k8s-runtime` connects to a live Kubernetes cluster and inspects running workloads for security misconfigurations. Unlike static manifest scanning (which analyzes YAML files), this plugin queries the Kubernetes API to examine the actual state of pods, containers, and network policies in your cluster.

This is a **dynamic-runtime** track plugin: it requires network access to a Kubernetes cluster, uses active risk classification, and requires user confirmation before scanning. It supports both in-cluster execution (e.g., running as a CronJob) and external kubeconfig-based access.

## Use Cases

### Pre-Production Security Gate

Before promoting workloads to production, scan the staging cluster to verify that no containers run as root, all images are pinned to specific versions or digests, and resource limits are properly configured. Catch misconfigurations that passed static analysis but were overridden at deployment time.

### Runtime Drift Detection

Your Terraform and Helm charts specify `runAsNonRoot: true`, but a manual `kubectl edit` changed the security context. This plugin detects the actual running state, catching drift between declared infrastructure-as-code and live cluster reality.

### Cluster Hardening Audit

Run a comprehensive scan across all namespaces to produce an inventory of security issues: privileged containers, missing network policies, auto-mounted service account tokens, and dangerous Linux capabilities. Use the findings to prioritize hardening work.

### CIS Kubernetes Benchmark Compliance

Map findings directly to CIS Kubernetes Benchmark controls (5.1.x through 5.5.x), NIST-800-53 controls, and PCI-DSS requirements. Generate evidence for compliance audits without manual cluster inspection.

## Rules

| ID | Description | Severity | CWE | CIS |
|----|-------------|----------|-----|-----|
| KRUNT-001 | Container running as root | High | CWE-250 | 5.2.6 |
| KRUNT-002 | Privileged container | Critical | CWE-250 | 5.2.1 |
| KRUNT-003 | Host namespace sharing (PID/Network/IPC) | High | CWE-653 | 5.2.2-4 |
| KRUNT-004 | No NetworkPolicy in namespace | Medium | CWE-284 | 5.3.2 |
| KRUNT-005 | Missing CPU or memory resource limits | Medium | CWE-770 | 5.4.1 |
| KRUNT-006 | Unpinned container image (:latest or no tag) | Medium | CWE-829 | 5.5.1 |
| KRUNT-007 | Service account token auto-mounted | Low | CWE-668 | 5.1.6 |
| KRUNT-008 | Dangerous Linux capabilities (SYS_ADMIN, NET_RAW, ALL, etc.) | High | CWE-250 | 5.2.7-9 |

### Dangerous Capabilities (KRUNT-008)

The following Linux capabilities are flagged: `SYS_ADMIN`, `NET_RAW`, `ALL`, `SYS_PTRACE`, `NET_ADMIN`, `DAC_OVERRIDE`.

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `KUBECONFIG` | Path to kubeconfig file | `~/.kube/config` |

The plugin automatically detects in-cluster configuration when running inside a Kubernetes pod. When running externally, it falls back to the `KUBECONFIG` environment variable or `~/.kube/config`.

### Tool Input Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace` | string | No | Kubernetes namespace to scan. Scans all namespaces if omitted. |

## Installation

### Via Nox (recommended)

```bash
nox plugin install Nox-HQ/nox-plugin-k8s-runtime
```

### Standalone

```bash
git clone https://github.com/Nox-HQ/nox-plugin-k8s-runtime.git
cd nox-plugin-k8s-runtime
go build -o nox-plugin-k8s-runtime .
```

## Development

```bash
# Build
go build ./...

# Run tests (no cluster needed -- uses fake clientset)
go test -race -v ./...

# Lint
golangci-lint run
```

## Architecture

The plugin is built on the Nox plugin SDK and communicates via the Nox plugin protocol over stdio.

**Scan pipeline:**

1. **Connect** -- Build Kubernetes client (in-cluster config or kubeconfig fallback). If the cluster is unreachable, return a diagnostic error without crashing.

2. **List resources** -- Fetch all pods and network policies in the target namespace (or all namespaces).

3. **Container-level checks** -- For each pod, iterate over both init containers and regular containers:
   - **KRUNT-001**: Check `effectiveSecurityContext` for `runAsUser: 0` or missing `runAsNonRoot: true`.
   - **KRUNT-002**: Check for `privileged: true`.
   - **KRUNT-005**: Verify CPU and memory limits are set.
   - **KRUNT-006**: Detect unpinned images (`:latest`, no tag, no `@sha256:` digest).
   - **KRUNT-008**: Flag dangerous Linux capabilities in the `add` list.

4. **Pod-level checks** -- For each pod:
   - **KRUNT-003**: Check `hostPID`, `hostNetwork`, `hostIPC`.
   - **KRUNT-004**: Verify the pod's namespace has at least one NetworkPolicy.
   - **KRUNT-007**: Check `automountServiceAccountToken` defaults.

5. **Security context merging** -- The `effectiveSecurityContext` helper merges pod-level `PodSecurityContext` with container-level `SecurityContext`. Container settings override pod settings.

6. **Output** -- Each finding includes a `k8s://` path (e.g., `k8s://production/Pod/web-app/nginx`) and metadata for namespace, pod, and container names.

## Contributing

Contributions are welcome. Please open an issue first to discuss proposed changes.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Write tests using `fake.NewSimpleClientset` (no real cluster needed)
4. Ensure `go test ./...` and `golangci-lint run` pass
5. Submit a pull request

## License

Apache-2.0
