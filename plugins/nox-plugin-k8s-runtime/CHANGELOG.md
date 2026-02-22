# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-02-22

### Added

- Initial release with 8 Kubernetes runtime security rules (KRUNT-001 through KRUNT-008)
- Live cluster scanning via Kubernetes API (in-cluster and kubeconfig support)
- Container-level checks: root execution, privileged mode, resource limits, unpinned images, dangerous capabilities
- Pod-level checks: host namespace sharing, network policy enforcement, service account token auto-mount
- Compliance mappings: CIS, NIST-800-53, PCI-DSS, OWASP Top 10
