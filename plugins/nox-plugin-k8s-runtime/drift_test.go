package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const podManifest = `
apiVersion: v1
kind: Pod
metadata:
  name: web
  namespace: default
spec:
  containers:
  - name: app
    image: ghcr.io/example/app:1.2.3
    resources:
      limits:
        cpu: "500m"
        memory: "256Mi"
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
`

const deploymentManifest = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
spec:
  template:
    spec:
      containers:
      - name: server
        image: ghcr.io/example/api:2.0.0
        resources:
          limits:
            cpu: "1"
            memory: "512Mi"
`

func writeIaCDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		full := filepath.Join(dir, name)
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func TestLoadIaCManifests_PodAndDeployment(t *testing.T) {
	dir := writeIaCDir(t, map[string]string{
		"web.yaml":      podManifest,
		"api.yaml":      deploymentManifest,
		"unrelated.txt": "ignored",
	})
	wls, err := loadIaCManifests(dir)
	if err != nil {
		t.Fatalf("loadIaCManifests: %v", err)
	}
	if _, ok := wls["default/web"]; !ok {
		t.Errorf("missing default/web; got keys=%v", keysOf(wls))
	}
	if _, ok := wls["prod/api"]; !ok {
		t.Errorf("missing prod/api; got keys=%v", keysOf(wls))
	}
}

func TestLoadIaCManifests_MultiDoc(t *testing.T) {
	multi := podManifest + "\n---\n" + deploymentManifest
	dir := writeIaCDir(t, map[string]string{"all.yaml": multi})
	wls, err := loadIaCManifests(dir)
	if err != nil {
		t.Fatalf("loadIaCManifests: %v", err)
	}
	if len(wls) != 2 {
		t.Errorf("expected 2 workloads from multi-doc, got %d: %v", len(wls), keysOf(wls))
	}
}

func TestScanDrift_ImageDrift(t *testing.T) {
	dir := writeIaCDir(t, map[string]string{"web.yaml": podManifest})

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "ghcr.io/example/app:9.9.9-hotfix", // drifted
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("500m"),
						corev1.ResourceMemory: resource.MustParse("256Mi"),
					},
				},
			}},
		},
	}
	s := NewScanner(fake.NewSimpleClientset(pod))
	findings, err := s.ScanDrift(context.Background(), "default", dir)
	if err != nil {
		t.Fatalf("ScanDrift: %v", err)
	}
	if !hasRule(findings, "KDRIFT-001") {
		t.Errorf("expected KDRIFT-001 image drift; got %v", ruleSet(findings))
	}
}

func TestScanDrift_LimitsDrift_Removed(t *testing.T) {
	dir := writeIaCDir(t, map[string]string{"web.yaml": podManifest})

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "ghcr.io/example/app:1.2.3",
				// limits omitted entirely — drift from declared
			}},
		},
	}
	s := NewScanner(fake.NewSimpleClientset(pod))
	findings, _ := s.ScanDrift(context.Background(), "default", dir)
	if !hasRule(findings, "KDRIFT-002") {
		t.Errorf("expected KDRIFT-002 limits drift; got %v", ruleSet(findings))
	}
}

func TestScanDrift_SecurityContextDrift_RootAdded(t *testing.T) {
	dir := writeIaCDir(t, map[string]string{"web.yaml": podManifest})

	root := int64(0)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "ghcr.io/example/app:1.2.3",
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("500m"),
						corev1.ResourceMemory: resource.MustParse("256Mi"),
					},
				},
				SecurityContext: &corev1.SecurityContext{RunAsUser: &root},
			}},
		},
	}
	s := NewScanner(fake.NewSimpleClientset(pod))
	findings, _ := s.ScanDrift(context.Background(), "default", dir)
	if !hasRule(findings, "KDRIFT-003") {
		t.Errorf("expected KDRIFT-003 securityContext drift; got %v", ruleSet(findings))
	}
}

func TestScanDrift_UnmanagedWorkload(t *testing.T) {
	dir := writeIaCDir(t, map[string]string{"web.yaml": podManifest})

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "rogue", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "x", Image: "alpine:3.19"}},
		},
	}
	s := NewScanner(fake.NewSimpleClientset(pod))
	findings, _ := s.ScanDrift(context.Background(), "default", dir)
	if !hasRule(findings, "KDRIFT-004") {
		t.Errorf("expected KDRIFT-004 unmanaged workload; got %v", ruleSet(findings))
	}
}

func TestScanDrift_NoDrift_NoFindings(t *testing.T) {
	dir := writeIaCDir(t, map[string]string{"web.yaml": podManifest})

	nonRoot := true
	user := int64(1000)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "ghcr.io/example/app:1.2.3",
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("500m"),
						corev1.ResourceMemory: resource.MustParse("256Mi"),
					},
				},
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: &nonRoot, RunAsUser: &user},
			}},
		},
	}
	s := NewScanner(fake.NewSimpleClientset(pod))
	findings, _ := s.ScanDrift(context.Background(), "default", dir)
	if len(findings) != 0 {
		t.Errorf("expected zero findings when state matches IaC; got %d: %v",
			len(findings), ruleSet(findings))
	}
}

func TestPodWorkloadKey_OwnerReplicaSet(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api-7d4b9c-abc12",
			Namespace: "prod",
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "api-7d4b9c"}},
		},
	}
	got := podWorkloadKey(pod)
	if got != "prod/api" {
		t.Errorf("expected prod/api, got %q", got)
	}
}

func TestPodWorkloadKey_OwnerDeployment(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api-7d4b9c-abc12",
			Namespace: "prod",
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "api"}},
		},
	}
	got := podWorkloadKey(pod)
	if got != "prod/api" {
		t.Errorf("expected prod/api, got %q", got)
	}
}

func TestCompareSecurityContext_PrivilegedAdded(t *testing.T) {
	priv := true
	a := &corev1.SecurityContext{Privileged: &priv}
	d := &corev1.SecurityContext{}
	msg, drifted := compareSecurityContext(nil, a, nil, d)
	if !drifted {
		t.Fatalf("expected drift")
	}
	if msg == "" {
		t.Fatalf("expected message, got empty")
	}
}

func TestCompareSecurityContext_TightenedNotDrift(t *testing.T) {
	// Declared no securityContext; running adds runAsNonRoot=true → tightening.
	nonRoot := true
	a := &corev1.SecurityContext{RunAsNonRoot: &nonRoot}
	_, drifted := compareSecurityContext(nil, a, nil, nil)
	if drifted {
		t.Errorf("tightening security context must not be flagged as drift")
	}
}

func TestHandleDrift_MissingIacPathErrors(t *testing.T) {
	resp, err := handleDrift(context.Background(), sdk.ToolRequest{Input: map[string]any{}})
	if err != nil {
		t.Fatalf("handleDrift returned error: %v", err)
	}
	if len(resp.GetDiagnostics()) == 0 {
		t.Errorf("expected diagnostic when iac_path missing")
	}
}

func keysOf(m map[string]iacWorkload) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func hasRule(findings []Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func ruleSet(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.RuleID+"="+string(f.Severity))
	}
	return out
}

// hush unused
var _ = pluginv1.Severity_SEVERITY_HIGH
