# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- `drift` tool: compare live cluster workloads against declared IaC manifests
  (Pod, Deployment, StatefulSet, DaemonSet) and emit drift findings.
- KDRIFT-001 (image), KDRIFT-002 (resource limits), KDRIFT-003 (security
  context regression), KDRIFT-004 (unmanaged workload).
- Multi-document YAML loader; owner-reference based workload identity.
- 9 new tests covering loader, comparators, and tool wiring.

## [0.1.0] - 2026-02-22

### Added

- Initial release with 8 Kubernetes runtime security rules (KRUNT-001 through KRUNT-008)
- Live cluster scanning via Kubernetes API (in-cluster and kubeconfig support)
- Container-level checks: root execution, privileged mode, resource limits, unpinned images, dangerous capabilities
- Pod-level checks: host namespace sharing, network policy enforcement, service account token auto-mount
- Compliance mappings: CIS, NIST-800-53, PCI-DSS, OWASP Top 10
