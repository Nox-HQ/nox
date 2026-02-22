package main

import (
	"context"
	"fmt"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Finding represents a single security finding from the k8s runtime scan.
type Finding struct {
	RuleID     string
	Severity   pluginv1.Severity
	Confidence pluginv1.Confidence
	Message    string
	CWE        string
	Path       string
	Namespace  string
	Pod        string
	Container  string
	Metadata   map[string]string
}

// Scanner inspects a Kubernetes cluster for runtime security issues.
type Scanner struct {
	client kubernetes.Interface
}

// NewScanner creates a Scanner with the given Kubernetes client.
func NewScanner(client kubernetes.Interface) *Scanner {
	return &Scanner{client: client}
}

// dangerousCaps lists Linux capabilities that are considered dangerous.
var dangerousCaps = map[string]bool{
	"SYS_ADMIN":    true,
	"NET_RAW":      true,
	"ALL":          true,
	"SYS_PTRACE":   true,
	"NET_ADMIN":    true,
	"DAC_OVERRIDE": true,
}

// ScanCluster inspects pods in the given namespace (or all namespaces if empty)
// and returns security findings.
func (s *Scanner) ScanCluster(ctx context.Context, namespace string) ([]Finding, error) {
	pods, err := s.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing pods: %w", err)
	}

	netPols, err := s.client.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing network policies: %w", err)
	}

	namespacesWithNetPol := make(map[string]bool)
	for i := range netPols.Items {
		namespacesWithNetPol[netPols.Items[i].Namespace] = true
	}

	var findings []Finding

	for i := range pods.Items {
		pod := &pods.Items[i]

		// Scan init containers.
		for j := range pod.Spec.InitContainers {
			c := &pod.Spec.InitContainers[j]
			findings = append(findings, s.checkContainer(pod, c)...)
		}

		// Scan regular containers.
		for j := range pod.Spec.Containers {
			c := &pod.Spec.Containers[j]
			findings = append(findings, s.checkContainer(pod, c)...)
		}

		// Pod-level checks.
		findings = append(findings, s.checkHostNamespace(pod)...)
		findings = append(findings, s.checkNetworkPolicy(pod, namespacesWithNetPol)...)
		findings = append(findings, s.checkServiceAccountToken(pod)...)
	}

	return findings, nil
}

// checkContainer runs container-level checks (KRUNT-001, 002, 005, 006, 008).
func (s *Scanner) checkContainer(pod *corev1.Pod, container *corev1.Container) []Finding {
	var findings []Finding
	esc := effectiveSecurityContext(pod.Spec.SecurityContext, container.SecurityContext)
	path := containerPath(pod.Namespace, pod.Name, container.Name)

	findings = append(findings, checkRunAsRoot(pod, container, esc, path)...)
	findings = append(findings, checkPrivileged(pod, container, esc, path)...)
	findings = append(findings, checkResourceLimits(pod, container, path)...)
	findings = append(findings, checkUnpinnedImage(pod, container, path)...)
	findings = append(findings, checkDangerousCaps(pod, container, esc, path)...)

	return findings
}

// containerPath builds the k8s:// path for a container-level finding.
func containerPath(namespace, podName, containerName string) string {
	return fmt.Sprintf("k8s://%s/Pod/%s/%s", namespace, podName, containerName)
}

// podPath builds the k8s:// path for a pod-level finding.
func podPath(namespace, podName string) string {
	return fmt.Sprintf("k8s://%s/Pod/%s", namespace, podName)
}

// effectiveSecurityContext merges the pod-level and container-level security contexts.
// Container-level settings override pod-level settings.
func effectiveSecurityContext(pod *corev1.PodSecurityContext, container *corev1.SecurityContext) *corev1.SecurityContext {
	if container != nil && pod == nil {
		return container
	}
	if container == nil && pod == nil {
		return nil
	}

	// Start with pod-level values.
	effective := &corev1.SecurityContext{}
	if pod != nil {
		if pod.RunAsNonRoot != nil {
			effective.RunAsNonRoot = pod.RunAsNonRoot
		}
		if pod.RunAsUser != nil {
			effective.RunAsUser = pod.RunAsUser
		}
	}

	// Container-level overrides.
	if container != nil {
		if container.RunAsNonRoot != nil {
			effective.RunAsNonRoot = container.RunAsNonRoot
		}
		if container.RunAsUser != nil {
			effective.RunAsUser = container.RunAsUser
		}
		if container.Privileged != nil {
			effective.Privileged = container.Privileged
		}
		if container.Capabilities != nil {
			effective.Capabilities = container.Capabilities
		}
	}

	return effective
}

// checkRunAsRoot checks KRUNT-001: Container running as root.
func checkRunAsRoot(pod *corev1.Pod, container *corev1.Container, esc *corev1.SecurityContext, path string) []Finding {
	if esc == nil {
		return []Finding{{
			RuleID:     "KRUNT-001",
			Severity:   pluginv1.Severity_SEVERITY_HIGH,
			Confidence: pluginv1.Confidence_CONFIDENCE_MEDIUM,
			Message:    fmt.Sprintf("Container %q has no security context — may run as root", container.Name),
			CWE:        "CWE-250",
			Path:       path,
			Namespace:  pod.Namespace,
			Pod:        pod.Name,
			Container:  container.Name,
		}}
	}

	// Explicitly running as root user.
	if esc.RunAsUser != nil && *esc.RunAsUser == 0 {
		return []Finding{{
			RuleID:     "KRUNT-001",
			Severity:   pluginv1.Severity_SEVERITY_HIGH,
			Confidence: pluginv1.Confidence_CONFIDENCE_HIGH,
			Message:    fmt.Sprintf("Container %q runs as root (runAsUser: 0)", container.Name),
			CWE:        "CWE-250",
			Path:       path,
			Namespace:  pod.Namespace,
			Pod:        pod.Name,
			Container:  container.Name,
		}}
	}

	// runAsNonRoot not set to true.
	if esc.RunAsNonRoot == nil || !*esc.RunAsNonRoot {
		// Only flag if runAsUser is also not set to a non-zero value.
		if esc.RunAsUser == nil {
			return []Finding{{
				RuleID:     "KRUNT-001",
				Severity:   pluginv1.Severity_SEVERITY_HIGH,
				Confidence: pluginv1.Confidence_CONFIDENCE_MEDIUM,
				Message:    fmt.Sprintf("Container %q does not enforce non-root execution", container.Name),
				CWE:        "CWE-250",
				Path:       path,
				Namespace:  pod.Namespace,
				Pod:        pod.Name,
				Container:  container.Name,
			}}
		}
	}

	return nil
}

// checkPrivileged checks KRUNT-002: Privileged container.
func checkPrivileged(pod *corev1.Pod, container *corev1.Container, esc *corev1.SecurityContext, path string) []Finding {
	if esc != nil && esc.Privileged != nil && *esc.Privileged {
		return []Finding{{
			RuleID:     "KRUNT-002",
			Severity:   pluginv1.Severity_SEVERITY_CRITICAL,
			Confidence: pluginv1.Confidence_CONFIDENCE_HIGH,
			Message:    fmt.Sprintf("Container %q runs in privileged mode", container.Name),
			CWE:        "CWE-250",
			Path:       path,
			Namespace:  pod.Namespace,
			Pod:        pod.Name,
			Container:  container.Name,
		}}
	}
	return nil
}

// checkHostNamespace checks KRUNT-003: Host namespace sharing (pod-level).
func (s *Scanner) checkHostNamespace(pod *corev1.Pod) []Finding {
	var findings []Finding
	path := podPath(pod.Namespace, pod.Name)

	if pod.Spec.HostPID {
		findings = append(findings, Finding{
			RuleID:     "KRUNT-003",
			Severity:   pluginv1.Severity_SEVERITY_HIGH,
			Confidence: pluginv1.Confidence_CONFIDENCE_HIGH,
			Message:    fmt.Sprintf("Pod %q shares host PID namespace", pod.Name),
			CWE:        "CWE-653",
			Path:       path,
			Namespace:  pod.Namespace,
			Pod:        pod.Name,
			Metadata:   map[string]string{"sharing": "hostPID"},
		})
	}
	if pod.Spec.HostNetwork {
		findings = append(findings, Finding{
			RuleID:     "KRUNT-003",
			Severity:   pluginv1.Severity_SEVERITY_HIGH,
			Confidence: pluginv1.Confidence_CONFIDENCE_HIGH,
			Message:    fmt.Sprintf("Pod %q shares host network namespace", pod.Name),
			CWE:        "CWE-653",
			Path:       path,
			Namespace:  pod.Namespace,
			Pod:        pod.Name,
			Metadata:   map[string]string{"sharing": "hostNetwork"},
		})
	}
	if pod.Spec.HostIPC {
		findings = append(findings, Finding{
			RuleID:     "KRUNT-003",
			Severity:   pluginv1.Severity_SEVERITY_HIGH,
			Confidence: pluginv1.Confidence_CONFIDENCE_HIGH,
			Message:    fmt.Sprintf("Pod %q shares host IPC namespace", pod.Name),
			CWE:        "CWE-653",
			Path:       path,
			Namespace:  pod.Namespace,
			Pod:        pod.Name,
			Metadata:   map[string]string{"sharing": "hostIPC"},
		})
	}

	return findings
}

// checkNetworkPolicy checks KRUNT-004: No network policy in namespace.
func (s *Scanner) checkNetworkPolicy(pod *corev1.Pod, namespacesWithNetPol map[string]bool) []Finding {
	if namespacesWithNetPol[pod.Namespace] {
		return nil
	}
	return []Finding{{
		RuleID:     "KRUNT-004",
		Severity:   pluginv1.Severity_SEVERITY_MEDIUM,
		Confidence: pluginv1.Confidence_CONFIDENCE_MEDIUM,
		Message:    fmt.Sprintf("Namespace %q has no NetworkPolicy — all traffic is allowed", pod.Namespace),
		CWE:        "CWE-284",
		Path:       podPath(pod.Namespace, pod.Name),
		Namespace:  pod.Namespace,
		Pod:        pod.Name,
	}}
}

// checkResourceLimits checks KRUNT-005: No resource limits.
func checkResourceLimits(pod *corev1.Pod, container *corev1.Container, path string) []Finding {
	limits := container.Resources.Limits
	if limits == nil {
		return []Finding{{
			RuleID:     "KRUNT-005",
			Severity:   pluginv1.Severity_SEVERITY_MEDIUM,
			Confidence: pluginv1.Confidence_CONFIDENCE_HIGH,
			Message:    fmt.Sprintf("Container %q has no resource limits", container.Name),
			CWE:        "CWE-770",
			Path:       path,
			Namespace:  pod.Namespace,
			Pod:        pod.Name,
			Container:  container.Name,
		}}
	}

	var missing []string
	if _, ok := limits[corev1.ResourceCPU]; !ok {
		missing = append(missing, "cpu")
	}
	if _, ok := limits[corev1.ResourceMemory]; !ok {
		missing = append(missing, "memory")
	}
	if len(missing) > 0 {
		return []Finding{{
			RuleID:     "KRUNT-005",
			Severity:   pluginv1.Severity_SEVERITY_MEDIUM,
			Confidence: pluginv1.Confidence_CONFIDENCE_HIGH,
			Message:    fmt.Sprintf("Container %q missing resource limits: %s", container.Name, strings.Join(missing, ", ")),
			CWE:        "CWE-770",
			Path:       path,
			Namespace:  pod.Namespace,
			Pod:        pod.Name,
			Container:  container.Name,
			Metadata:   map[string]string{"missing_limits": strings.Join(missing, ",")},
		}}
	}

	return nil
}

// checkUnpinnedImage checks KRUNT-006: Unpinned container image.
func checkUnpinnedImage(pod *corev1.Pod, container *corev1.Container, path string) []Finding {
	if isUnpinnedImage(container.Image) {
		return []Finding{{
			RuleID:     "KRUNT-006",
			Severity:   pluginv1.Severity_SEVERITY_MEDIUM,
			Confidence: pluginv1.Confidence_CONFIDENCE_HIGH,
			Message:    fmt.Sprintf("Container %q uses unpinned image %q", container.Name, container.Image),
			CWE:        "CWE-829",
			Path:       path,
			Namespace:  pod.Namespace,
			Pod:        pod.Name,
			Container:  container.Name,
			Metadata:   map[string]string{"image": container.Image},
		}}
	}
	return nil
}

// isUnpinnedImage returns true if the image reference is unpinned.
// An image is unpinned if it uses :latest, has no tag, or lacks a @sha256: digest.
func isUnpinnedImage(image string) bool {
	if image == "" {
		return true
	}

	// If pinned by digest, always considered pinned.
	if strings.Contains(image, "@sha256:") {
		return false
	}

	// Find the last colon to check for a tag.
	lastColon := strings.LastIndex(image, ":")
	if lastColon == -1 {
		// No colon at all — no tag, unpinned.
		return true
	}

	// Check if the part after the last colon contains a slash.
	// If it does, the colon is part of a registry:port pattern, not a tag.
	suffix := image[lastColon+1:]
	if strings.Contains(suffix, "/") {
		// e.g., myregistry:5000/app — no tag, unpinned.
		return true
	}

	// The suffix is a tag. Check if it's "latest".
	return suffix == "latest"
}

// checkServiceAccountToken checks KRUNT-007: SA token auto-mounted.
func (s *Scanner) checkServiceAccountToken(pod *corev1.Pod) []Finding {
	// automountServiceAccountToken defaults to true when unset.
	if pod.Spec.AutomountServiceAccountToken != nil && !*pod.Spec.AutomountServiceAccountToken {
		return nil
	}
	return []Finding{{
		RuleID:     "KRUNT-007",
		Severity:   pluginv1.Severity_SEVERITY_LOW,
		Confidence: pluginv1.Confidence_CONFIDENCE_MEDIUM,
		Message:    fmt.Sprintf("Pod %q auto-mounts service account token", pod.Name),
		CWE:        "CWE-668",
		Path:       podPath(pod.Namespace, pod.Name),
		Namespace:  pod.Namespace,
		Pod:        pod.Name,
	}}
}

// checkDangerousCaps checks KRUNT-008: Dangerous capabilities.
func checkDangerousCaps(pod *corev1.Pod, container *corev1.Container, esc *corev1.SecurityContext, path string) []Finding {
	if esc == nil || esc.Capabilities == nil {
		return nil
	}

	var found []string
	for _, cap := range esc.Capabilities.Add {
		if dangerousCaps[string(cap)] {
			found = append(found, string(cap))
		}
	}

	if len(found) > 0 {
		return []Finding{{
			RuleID:     "KRUNT-008",
			Severity:   pluginv1.Severity_SEVERITY_HIGH,
			Confidence: pluginv1.Confidence_CONFIDENCE_HIGH,
			Message:    fmt.Sprintf("Container %q adds dangerous capabilities: %s", container.Name, strings.Join(found, ", ")),
			CWE:        "CWE-250",
			Path:       path,
			Namespace:  pod.Namespace,
			Pod:        pod.Name,
			Container:  container.Name,
			Metadata:   map[string]string{"capabilities": strings.Join(found, ",")},
		}}
	}

	return nil
}
