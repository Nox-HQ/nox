package iac

import (
	"strings"
	"testing"
)

// IAC-464 was built on k8sManifestPrefix, which is
// `(?is)apiVersion:...kind:...` — dotall, so its trailing `.*` spans the whole
// file, and case-insensitive. Appending the bare word `Namespace` matched that
// word ANYWHERE after the first kind: line, which includes the `namespace:`
// field that nearly every namespaced manifest carries.
//
// The result: a ConfigMap declaring `namespace: example` was reported as
// "K8s Namespace defined", at medium severity, in every Kubernetes repository
// nox has ever scanned.
func TestIAC464MatchesTheKindNotTheWord(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want bool
	}{
		{
			name: "an actual Namespace",
			yaml: "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: example\n",
			want: true,
		},
		{
			name: "a ConfigMap that merely declares its namespace",
			yaml: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n  namespace: example\ndata:\n  k: v\n",
			want: false,
		},
		{
			name: "a custom resource that declares its namespace",
			yaml: "apiVersion: example.com/v1\nkind: SomethingElse\nmetadata:\n  name: thing\n  namespace: example\n",
			want: false,
		},
		{
			name: "the word in a comment",
			yaml: "# creates a Namespace later\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n",
			want: false,
		},
		{
			name: "a Namespace declared after another document",
			yaml: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n---\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: example\n",
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleFires(t, "manifest.yaml", tc.yaml, "IAC-464")
			if got != tc.want {
				t.Errorf("IAC-464 fired = %v, want %v for:\n%s", got, tc.want, tc.yaml)
			}
		})
	}
}

// The description has always said "(informational)". Reporting it at medium
// inflated every Kubernetes repository's medium count with a fact rather than
// a problem.
func TestIAC464IsInformationalSeverity(t *testing.T) {
	for _, r := range builtinExpandedIaCRules() {
		if r.ID != "IAC-464" {
			continue
		}
		if !strings.Contains(r.Description, "informational") {
			t.Fatalf("description no longer says informational: %q", r.Description)
		}
		if string(r.Severity) != "info" {
			t.Errorf("severity = %q, want info — the description calls it informational", r.Severity)
		}
		return
	}
	t.Fatal("IAC-464 not found")
}
