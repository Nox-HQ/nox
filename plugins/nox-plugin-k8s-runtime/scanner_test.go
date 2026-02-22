package main

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func boolPtr(b bool) *bool    { return &b }
func int64Ptr(i int64) *int64 { return &i }

// --- KRUNT-001: Container running as root ---

func TestKRUNT001_RunAsUserZero(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "root-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{
					RunAsUser: int64Ptr(0),
				},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertHasRule(t, findings, "KRUNT-001")
}

func TestKRUNT001_RunAsNonRoot(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "safe-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{
					RunAsNonRoot: boolPtr(true),
				},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertNoRule(t, findings, "KRUNT-001")
}

func TestKRUNT001_NoSecurityContext(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "no-ctx-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:1.25",
			}},
		},
	}

	findings := scanPod(t, pod)
	assertHasRule(t, findings, "KRUNT-001")
}

func TestKRUNT001_PodLevelRunAsNonRoot(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-level", Namespace: "default"},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: boolPtr(true),
			},
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:1.25",
			}},
		},
	}

	findings := scanPod(t, pod)
	assertNoRule(t, findings, "KRUNT-001")
}

// --- KRUNT-002: Privileged container ---

func TestKRUNT002_Privileged(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "priv-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{
					Privileged: boolPtr(true),
				},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertHasRule(t, findings, "KRUNT-002")
}

func TestKRUNT002_NotPrivileged(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "safe-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{
					Privileged: boolPtr(false),
				},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertNoRule(t, findings, "KRUNT-002")
}

// --- KRUNT-003: Host namespace sharing ---

func TestKRUNT003_HostPID(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "hostpid-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			HostPID: true,
			Containers: []corev1.Container{{
				Name: "app", Image: "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertHasRule(t, findings, "KRUNT-003")
	assertMetadataValue(t, findings, "KRUNT-003", "sharing", "hostPID")
}

func TestKRUNT003_HostNetwork(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "hostnet-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			HostNetwork: true,
			Containers: []corev1.Container{{
				Name: "app", Image: "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertHasRule(t, findings, "KRUNT-003")
	assertMetadataValue(t, findings, "KRUNT-003", "sharing", "hostNetwork")
}

func TestKRUNT003_HostIPC(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "hostipc-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			HostIPC: true,
			Containers: []corev1.Container{{
				Name: "app", Image: "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertHasRule(t, findings, "KRUNT-003")
	assertMetadataValue(t, findings, "KRUNT-003", "sharing", "hostIPC")
}

func TestKRUNT003_NoHostSharing(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "safe-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app", Image: "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertNoRule(t, findings, "KRUNT-003")
}

// --- KRUNT-004: No network policy ---

func TestKRUNT004_NoNetworkPolicy(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app-pod", Namespace: "production"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app", Image: "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
			}},
		},
	}

	client := fake.NewSimpleClientset(pod)
	scanner := NewScanner(client)
	findings, err := scanner.ScanCluster(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}

	assertHasRule(t, findings, "KRUNT-004")
}

func TestKRUNT004_WithNetworkPolicy(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app-pod", Namespace: "production"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app", Image: "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
			}},
		},
	}

	netpol := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: "production"},
	}

	client := fake.NewSimpleClientset(pod, netpol)
	scanner := NewScanner(client)
	findings, err := scanner.ScanCluster(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}

	assertNoRule(t, findings, "KRUNT-004")
}

// --- KRUNT-005: No resource limits ---

func TestKRUNT005_NoLimits(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "no-limits-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "app",
				Image:           "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertHasRule(t, findings, "KRUNT-005")
}

func TestKRUNT005_WithLimits(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "limits-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "app",
				Image:           "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("500m"),
						corev1.ResourceMemory: resource.MustParse("256Mi"),
					},
				},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertNoRule(t, findings, "KRUNT-005")
}

func TestKRUNT005_MissingCPULimit(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "partial-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "app",
				Image:           "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse("256Mi"),
					},
				},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertHasRule(t, findings, "KRUNT-005")
}

// --- KRUNT-006: Unpinned container image ---

func TestKRUNT006_LatestTag(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "latest-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "app",
				Image:           "nginx:latest",
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertHasRule(t, findings, "KRUNT-006")
}

func TestKRUNT006_DigestPinned(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "digest-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "app",
				Image:           "nginx@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertNoRule(t, findings, "KRUNT-006")
}

func TestKRUNT006_RegistryPortNotTag(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "registry-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "app",
				Image:           "myregistry:5000/app:v1.2.3",
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertNoRule(t, findings, "KRUNT-006")
}

func TestKRUNT006_VersionTag(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "versioned-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "app",
				Image:           "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertNoRule(t, findings, "KRUNT-006")
}

// --- KRUNT-007: SA token auto-mounted ---

func TestKRUNT007_AutomountDefault(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "automount-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app", Image: "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertHasRule(t, findings, "KRUNT-007")
}

func TestKRUNT007_AutomountDisabled(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "no-automount-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken: boolPtr(false),
			Containers: []corev1.Container{{
				Name: "app", Image: "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertNoRule(t, findings, "KRUNT-007")
}

// --- KRUNT-008: Dangerous capabilities ---

func TestKRUNT008_SysAdmin(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "caps-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{
					RunAsNonRoot: boolPtr(true),
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{"SYS_ADMIN"},
					},
				},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertHasRule(t, findings, "KRUNT-008")
}

func TestKRUNT008_SafeCapability(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "safe-caps-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{
					RunAsNonRoot: boolPtr(true),
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{"NET_BIND_SERVICE"},
					},
				},
			}},
		},
	}

	findings := scanPod(t, pod)
	assertNoRule(t, findings, "KRUNT-008")
}

// --- effectiveSecurityContext ---

func TestEffectiveSecurityContext_ContainerOverridesPod(t *testing.T) {
	podSC := &corev1.PodSecurityContext{
		RunAsNonRoot: boolPtr(true),
		RunAsUser:    int64Ptr(1000),
	}
	containerSC := &corev1.SecurityContext{
		RunAsUser: int64Ptr(0), // Override to root.
	}

	esc := effectiveSecurityContext(podSC, containerSC)
	if esc.RunAsUser == nil || *esc.RunAsUser != 0 {
		t.Errorf("expected container-level RunAsUser=0, got %v", esc.RunAsUser)
	}
	// RunAsNonRoot should still be inherited from pod since container didn't set it.
	if esc.RunAsNonRoot == nil || !*esc.RunAsNonRoot {
		t.Error("expected pod-level RunAsNonRoot=true to be inherited")
	}
}

func TestEffectiveSecurityContext_BothNil(t *testing.T) {
	esc := effectiveSecurityContext(nil, nil)
	if esc != nil {
		t.Error("expected nil when both contexts are nil")
	}
}

func TestEffectiveSecurityContext_ContainerOnly(t *testing.T) {
	containerSC := &corev1.SecurityContext{
		Privileged: boolPtr(true),
	}

	esc := effectiveSecurityContext(nil, containerSC)
	if esc != containerSC {
		t.Error("expected container security context to be returned directly")
	}
}

// --- isUnpinnedImage ---

func TestIsUnpinnedImage(t *testing.T) {
	tests := []struct {
		image    string
		unpinned bool
	}{
		{"", true},
		{"nginx", true},
		{"nginx:latest", true},
		{"nginx:1.25", false},
		{"nginx:1.25-alpine", false},
		{"nginx@sha256:abcdef1234567890", false},
		{"myregistry:5000/app", true},        // Registry port, no tag.
		{"myregistry:5000/app:v1", false},    // Registry port + tag.
		{"myregistry:5000/app:latest", true}, // Registry port + latest.
		{"gcr.io/project/image:v2", false},
		{"gcr.io/project/image", true},
	}

	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			got := isUnpinnedImage(tt.image)
			if got != tt.unpinned {
				t.Errorf("isUnpinnedImage(%q) = %v, want %v", tt.image, got, tt.unpinned)
			}
		})
	}
}

// --- Empty cluster ---

func TestEmptyCluster(t *testing.T) {
	client := fake.NewSimpleClientset()
	scanner := NewScanner(client)
	findings, err := scanner.ScanCluster(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty cluster, got %d", len(findings))
	}
}

// --- Multi-namespace ---

func TestMultiNamespace(t *testing.T) {
	pod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-a", Namespace: "ns-a"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app", Image: "nginx:latest",
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
			}},
		},
	}
	pod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-b", Namespace: "ns-b"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app", Image: "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
			}},
		},
	}

	client := fake.NewSimpleClientset(pod1, pod2)
	scanner := NewScanner(client)

	// Scan all namespaces.
	all, err := scanner.ScanCluster(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}

	// Should have findings from both namespaces.
	namespaces := make(map[string]bool)
	for _, f := range all {
		namespaces[f.Namespace] = true
	}
	if !namespaces["ns-a"] || !namespaces["ns-b"] {
		t.Errorf("expected findings from both namespaces, got: %v", namespaces)
	}

	// Scan single namespace.
	nsA, err := scanner.ScanCluster(context.Background(), "ns-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range nsA {
		if f.Namespace != "ns-a" {
			t.Errorf("expected namespace ns-a, got %q", f.Namespace)
		}
	}
}

// --- Init containers ---

func TestInitContainerScanned(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "init-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "init",
				Image: "busybox:latest",
				SecurityContext: &corev1.SecurityContext{
					Privileged: boolPtr(true),
				},
			}},
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{
					RunAsNonRoot: boolPtr(true),
				},
			}},
		},
	}

	findings := scanPod(t, pod)
	// Init container should trigger KRUNT-002 (privileged) and KRUNT-006 (latest).
	assertHasRule(t, findings, "KRUNT-002")
	assertHasRule(t, findings, "KRUNT-006")

	// Verify the init container is named in the finding.
	for _, f := range findings {
		if f.RuleID == "KRUNT-002" && f.Container != "init" {
			t.Errorf("expected KRUNT-002 for init container, got container=%q", f.Container)
		}
	}
}

// --- Helpers ---

func scanPod(t *testing.T, pod *corev1.Pod, extraObjects ...runtime.Object) []Finding {
	t.Helper()

	objects := []runtime.Object{pod}
	objects = append(objects, extraObjects...)
	client := fake.NewSimpleClientset(objects...)
	scanner := NewScanner(client)
	findings, err := scanner.ScanCluster(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func assertHasRule(t *testing.T, findings []Finding, ruleID string) {
	t.Helper()
	for _, f := range findings {
		if f.RuleID == ruleID {
			return
		}
	}
	t.Errorf("expected finding %s but not found (got %d findings)", ruleID, len(findings))
}

func assertNoRule(t *testing.T, findings []Finding, ruleID string) {
	t.Helper()
	for _, f := range findings {
		if f.RuleID == ruleID {
			t.Errorf("unexpected finding %s: %s", ruleID, f.Message)
			return
		}
	}
}

func assertMetadataValue(t *testing.T, findings []Finding, ruleID, key, want string) {
	t.Helper()
	for _, f := range findings {
		if f.RuleID == ruleID {
			if got, ok := f.Metadata[key]; ok && got == want {
				return
			}
		}
	}
	t.Errorf("expected %s finding with metadata %s=%q", ruleID, key, want)
}
