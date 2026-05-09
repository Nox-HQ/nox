package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// iacWorkload is the desired-state PodSpec sourced from a manifest on disk,
// keyed by namespace+name (workload identity, not pod-instance identity).
type iacWorkload struct {
	Namespace string
	Name      string
	Spec      corev1.PodSpec
	Source    string // file path
}

// loadIaCManifests walks dir and parses every .yaml/.yml file looking for Pod,
// Deployment, StatefulSet, and DaemonSet manifests. Returns a map keyed by
// "namespace/name" -> desired PodSpec.
func loadIaCManifests(dir string) (map[string]iacWorkload, error) {
	out := make(map[string]iacWorkload)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		for _, doc := range splitYAMLDocs(raw) {
			wl, ok := parseManifest(doc, path)
			if !ok {
				continue
			}
			ns := wl.Namespace
			if ns == "" {
				ns = "default"
			}
			out[ns+"/"+wl.Name] = wl
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// splitYAMLDocs splits a multi-document YAML stream on `---` separators.
func splitYAMLDocs(raw []byte) [][]byte {
	parts := strings.Split(string(raw), "\n---")
	docs := make([][]byte, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		docs = append(docs, []byte(p))
	}
	return docs
}

// parseManifest extracts a workload PodSpec from a single YAML document.
// Supports Pod, Deployment, StatefulSet, DaemonSet kinds.
func parseManifest(doc []byte, source string) (iacWorkload, bool) {
	var meta struct {
		Kind     string `json:"kind"`
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
	}
	if err := yaml.Unmarshal(doc, &meta); err != nil {
		return iacWorkload{}, false
	}
	if meta.Metadata.Name == "" {
		return iacWorkload{}, false
	}

	wl := iacWorkload{
		Namespace: meta.Metadata.Namespace,
		Name:      meta.Metadata.Name,
		Source:    source,
	}

	switch meta.Kind {
	case "Pod":
		var pod corev1.Pod
		if err := yaml.Unmarshal(doc, &pod); err != nil {
			return iacWorkload{}, false
		}
		wl.Spec = pod.Spec
	case "Deployment":
		var d appsv1.Deployment
		if err := yaml.Unmarshal(doc, &d); err != nil {
			return iacWorkload{}, false
		}
		wl.Spec = d.Spec.Template.Spec
	case "StatefulSet":
		var s appsv1.StatefulSet
		if err := yaml.Unmarshal(doc, &s); err != nil {
			return iacWorkload{}, false
		}
		wl.Spec = s.Spec.Template.Spec
	case "DaemonSet":
		var d appsv1.DaemonSet
		if err := yaml.Unmarshal(doc, &d); err != nil {
			return iacWorkload{}, false
		}
		wl.Spec = d.Spec.Template.Spec
	default:
		return iacWorkload{}, false
	}
	return wl, true
}

// ScanDrift compares cluster state against IaC manifests and returns drift findings.
//
// Drift rules:
//   - KDRIFT-001 image differs from declared
//   - KDRIFT-002 resource limits differ from declared (or removed)
//   - KDRIFT-003 securityContext less restrictive than declared
//   - KDRIFT-004 running workload not present in IaC (unmanaged)
func (s *Scanner) ScanDrift(ctx context.Context, namespace, iacPath string) ([]Finding, error) {
	desired, err := loadIaCManifests(iacPath)
	if err != nil {
		return nil, fmt.Errorf("loading IaC manifests: %w", err)
	}

	pods, err := s.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing pods: %w", err)
	}

	var findings []Finding
	matched := make(map[string]bool)

	for i := range pods.Items {
		pod := &pods.Items[i]
		key := podWorkloadKey(pod)
		wl, ok := desired[key]
		if !ok {
			findings = append(findings, Finding{
				RuleID:     "KDRIFT-004",
				Severity:   pluginv1.Severity_SEVERITY_MEDIUM,
				Confidence: pluginv1.Confidence_CONFIDENCE_MEDIUM,
				Message:    fmt.Sprintf("Pod %q is running but not declared in IaC at %q", pod.Name, iacPath),
				CWE:        "CWE-710",
				Path:       podPath(pod.Namespace, pod.Name),
				Namespace:  pod.Namespace,
				Pod:        pod.Name,
				Metadata:   map[string]string{"iac_path": iacPath, "workload_key": key},
			})
			continue
		}
		matched[key] = true
		findings = append(findings, compareWorkload(pod, wl)...)
	}

	return findings, nil
}

// podWorkloadKey returns "namespace/workload-name" derived from owner references
// (Deployment/StatefulSet/DaemonSet/ReplicaSet) when present, falling back to
// the pod's own name.
func podWorkloadKey(pod *corev1.Pod) string {
	ns := pod.Namespace
	if ns == "" {
		ns = "default"
	}
	for _, owner := range pod.OwnerReferences {
		switch owner.Kind {
		case "ReplicaSet":
			// ReplicaSet name is "<deployment>-<hash>"; trim the hash suffix.
			if idx := strings.LastIndex(owner.Name, "-"); idx > 0 {
				return ns + "/" + owner.Name[:idx]
			}
			return ns + "/" + owner.Name
		case "Deployment", "StatefulSet", "DaemonSet":
			return ns + "/" + owner.Name
		}
	}
	return ns + "/" + pod.Name
}

// compareWorkload diffs a running pod against its declared spec.
func compareWorkload(pod *corev1.Pod, wl iacWorkload) []Finding {
	var findings []Finding

	desiredContainers := indexContainersByName(wl.Spec.Containers)

	for i := range pod.Spec.Containers {
		actual := &pod.Spec.Containers[i]
		desired, ok := desiredContainers[actual.Name]
		if !ok {
			continue
		}
		path := containerPath(pod.Namespace, pod.Name, actual.Name)

		if actual.Image != desired.Image {
			findings = append(findings, Finding{
				RuleID:     "KDRIFT-001",
				Severity:   pluginv1.Severity_SEVERITY_HIGH,
				Confidence: pluginv1.Confidence_CONFIDENCE_HIGH,
				Message: fmt.Sprintf("Container %q image drift: running %q, declared %q",
					actual.Name, actual.Image, desired.Image),
				CWE:       "CWE-829",
				Path:      path,
				Namespace: pod.Namespace,
				Pod:       pod.Name,
				Container: actual.Name,
				Metadata: map[string]string{
					"running_image":  actual.Image,
					"declared_image": desired.Image,
					"iac_source":     wl.Source,
				},
			})
		}

		if msg, drifted := compareLimits(actual.Resources, desired.Resources); drifted {
			findings = append(findings, Finding{
				RuleID:     "KDRIFT-002",
				Severity:   pluginv1.Severity_SEVERITY_MEDIUM,
				Confidence: pluginv1.Confidence_CONFIDENCE_HIGH,
				Message:    fmt.Sprintf("Container %q resource limits drift: %s", actual.Name, msg),
				CWE:        "CWE-770",
				Path:       path,
				Namespace:  pod.Namespace,
				Pod:        pod.Name,
				Container:  actual.Name,
				Metadata:   map[string]string{"iac_source": wl.Source},
			})
		}

		if msg, drifted := compareSecurityContext(
			pod.Spec.SecurityContext, actual.SecurityContext,
			wl.Spec.SecurityContext, desired.SecurityContext,
		); drifted {
			findings = append(findings, Finding{
				RuleID:     "KDRIFT-003",
				Severity:   pluginv1.Severity_SEVERITY_HIGH,
				Confidence: pluginv1.Confidence_CONFIDENCE_HIGH,
				Message:    fmt.Sprintf("Container %q securityContext drift: %s", actual.Name, msg),
				CWE:        "CWE-250",
				Path:       path,
				Namespace:  pod.Namespace,
				Pod:        pod.Name,
				Container:  actual.Name,
				Metadata:   map[string]string{"iac_source": wl.Source},
			})
		}
	}

	return findings
}

func indexContainersByName(cs []corev1.Container) map[string]*corev1.Container {
	out := make(map[string]*corev1.Container, len(cs))
	for i := range cs {
		out[cs[i].Name] = &cs[i]
	}
	return out
}

// compareLimits returns a drift message when CPU or memory limits diverge.
func compareLimits(actual, desired corev1.ResourceRequirements) (string, bool) {
	var msgs []string
	for _, key := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
		a, aOK := actual.Limits[key]
		d, dOK := desired.Limits[key]
		switch {
		case dOK && !aOK:
			msgs = append(msgs, fmt.Sprintf("%s limit removed (declared %s)", key, d.String()))
		case dOK && aOK && a.Cmp(d) != 0:
			msgs = append(msgs, fmt.Sprintf("%s limit %s != declared %s", key, a.String(), d.String()))
		}
	}
	if len(msgs) == 0 {
		return "", false
	}
	return strings.Join(msgs, "; "), true
}

// compareSecurityContext flags drift only when the running pod is *less*
// restrictive than declared (privilege escalation, root, dropped non-root
// enforcement, added dangerous caps). Tightening is not drift.
func compareSecurityContext(
	podPSC *corev1.PodSecurityContext, ctrSC *corev1.SecurityContext,
	desiredPSC *corev1.PodSecurityContext, desiredCtr *corev1.SecurityContext,
) (string, bool) {
	a := effectiveSecurityContext(podPSC, ctrSC)
	d := effectiveSecurityContext(desiredPSC, desiredCtr)

	var msgs []string

	desiredPrivileged := d != nil && d.Privileged != nil && *d.Privileged
	actualPrivileged := a != nil && a.Privileged != nil && *a.Privileged
	if actualPrivileged && !desiredPrivileged {
		msgs = append(msgs, "privileged enabled (not declared)")
	}

	desiredNonRoot := d != nil && d.RunAsNonRoot != nil && *d.RunAsNonRoot
	actualNonRoot := a != nil && a.RunAsNonRoot != nil && *a.RunAsNonRoot
	if desiredNonRoot && !actualNonRoot {
		msgs = append(msgs, "runAsNonRoot dropped")
	}

	desiredRoot := d != nil && d.RunAsUser != nil && *d.RunAsUser == 0
	actualRoot := a != nil && a.RunAsUser != nil && *a.RunAsUser == 0
	if actualRoot && !desiredRoot {
		msgs = append(msgs, "runAsUser=0 (not declared)")
	}

	added := newCapabilities(a, d)
	if len(added) > 0 {
		msgs = append(msgs, "added capabilities: "+strings.Join(added, ","))
	}

	if len(msgs) == 0 {
		return "", false
	}
	return strings.Join(msgs, "; "), true
}

// newCapabilities returns dangerous capabilities present in actual but not in desired.
func newCapabilities(actual, desired *corev1.SecurityContext) []string {
	if actual == nil || actual.Capabilities == nil {
		return nil
	}
	declared := make(map[string]bool)
	if desired != nil && desired.Capabilities != nil {
		for _, c := range desired.Capabilities.Add {
			declared[string(c)] = true
		}
	}
	var added []string
	for _, c := range actual.Capabilities.Add {
		name := string(c)
		if dangerousCaps[name] && !declared[name] {
			added = append(added, name)
		}
	}
	return added
}
