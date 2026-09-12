package iac

import "testing"

// Three of the eight end-of-text anchors could not be fixed by restoring the
// anchor, because the rules make ABSENCE claims and were written with presence
// patterns.
//
//	IAC-239  "Kustomize commonLabels missing standard labels"  `commonLabels:\s*$`
//	IAC-211  "Ansible Galaxy role without version pin"         `src:\s*[\w.-]+\s*$`
//	IAC-214  "Ansible collection without version pin"          `name:\s*[a-z_]+\.[a-z_]+\s*$`
//
// Each pattern says only that the thing EXISTS. Restoring `(?m)` would have
// made IAC-239 report every commonLabels block in every kustomization,
// correctly declared and all — a rule finally able to fire and wrong every time
// it did — and would have made IAC-211 report every `src:` in every Ansible
// copy and template task as an unpinned Galaxy role.
//
// So they move to the block-scoped absence matcher, which is the thing their
// descriptions were already describing. IAC-214 is retired into IAC-211 on the
// way: a requirements entry spells its dependency `src:` OR `name:`, never
// both, so the two rules partitioned one condition by spelling and each was
// blind to half of it.

const requirementsMixed = `roles:
  - src: geerlingguy.docker
  - src: geerlingguy.nginx
    version: 3.1.4
collections:
  - name: community.docker
  - name: ansible.posix
    version: 1.5.4
`

// ansibleTasks is why the anchor is a SEQUENCE ENTRY. `src:` in a copy task is
// a file path, and `- name:` opens a task. With `(?m)` and the shipped pattern
// both of these were reported as unpinned Galaxy dependencies.
const ansibleTasks = `- name: Install the config
  copy:
    src: files/app.conf
    dest: /etc/app.conf
- name: Restart the service
  service:
    name: app
    state: restarted
`

const kustomizationBareLabels = `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
commonLabels:
  team: platform
  tier: backend
`

const kustomizationStandardLabels = `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
commonLabels:
  app.kubernetes.io/name: podinfo
  app.kubernetes.io/managed-by: kustomize
`

// countRule returns how many times a rule fired.
func countRule(t *testing.T, path, body, rule string) int {
	t.Helper()
	var n int
	for _, id := range scanIDs(t, path, body) {
		if id == rule {
			n++
		}
	}
	return n
}

// TestIAC211ReportsOnlyTheUnpinnedEntries is both directions at once: the two
// entries with no `version` fire, the two with one do not. A rule that fired on
// all four would be as useless as one that fired on none.
func TestIAC211ReportsOnlyTheUnpinnedEntries(t *testing.T) {
	if got := countRule(t, "requirements.yml", requirementsMixed, "IAC-211"); got != 2 {
		t.Errorf("IAC-211 fired %d times on a requirements file with 2 unpinned and 2 "+
			"pinned entries; want 2", got)
	}
}

// TestTheSpanIsOneListItem. The `version` on the NEXT entry must not satisfy
// this one — that is the difference between a yaml-block span anchored on the
// sequence item and one anchored on the `roles:` key.
func TestTheSpanIsOneListItem(t *testing.T) {
	const adjacent = `roles:
  - src: geerlingguy.docker
  - src: geerlingguy.nginx
    version: 3.1.4
`
	if got := countRule(t, "requirements.yml", adjacent, "IAC-211"); got != 1 {
		t.Errorf("IAC-211 fired %d times; the unpinned first entry must report and the "+
			"version on the second must not cover it; want 1", got)
	}
}

// TestIAC211DoesNotReportTaskSourcePaths is the false positive that restoring
// the anchor alone would have created.
func TestIAC211DoesNotReportTaskSourcePaths(t *testing.T) {
	if got := countRule(t, "tasks.yml", ansibleTasks, "IAC-211"); got != 0 {
		t.Errorf("IAC-211 fired %d times on Ansible tasks; `src:` in a copy module is a "+
			"file path and `- name:` opens a task, neither is a Galaxy dependency", got)
	}
}

// TestIAC211IsScopedToRequirementsFiles. The file pattern narrows; the anchor
// decides. Measured: without the narrowing the anchor reported
// `- name: dcgm.rules`, a Prometheus rule GROUP, in kubernetes/examples.
func TestIAC211IsScopedToRequirementsFiles(t *testing.T) {
	const prometheusRule = `apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
spec:
  groups:
    - name: dcgm.rules
      rules:
        - alert: GPUHot
          expr: DCGM_FI_DEV_GPU_TEMP > 85
`
	if got := countRule(t, "prometheus-rule.yaml", prometheusRule, "IAC-211"); got != 0 {
		t.Errorf("IAC-211 fired %d times on a PrometheusRule; a rule group name is not a "+
			"Galaxy dependency", got)
	}
}

// TestIAC214IsRetiredIntoIAC211 keeps the waiver alias honest. Deleting the ID
// outright would un-waive, in every consuming repo, findings an operator
// accepted against it.
func TestIAC214IsRetiredIntoIAC211(t *testing.T) {
	set := NewAnalyzer().Rules()
	if _, ok := set.ByID("IAC-214"); ok {
		t.Error("IAC-214 is still a live rule; it reports the same condition as IAC-211")
	}
	r, ok := set.ByID("IAC-211")
	if !ok {
		t.Fatal("IAC-211 not found")
	}
	var found bool
	for _, ret := range r.Retires {
		if ret.ID == "IAC-214" {
			found = true
			if ret.Pattern == "" {
				t.Error("IAC-214's retirement carries no pattern, so a waiver written " +
					"against it cannot reproduce its fingerprint")
			}
		}
	}
	if !found {
		t.Error("IAC-211 does not carry the IAC-214 alias; every waiver written against " +
			"IAC-214 would silently stop matching")
	}
}

// TestIAC239ReportsOnlyTheBlockWithoutStandardLabels, both directions.
func TestIAC239ReportsOnlyTheBlockWithoutStandardLabels(t *testing.T) {
	if got := countRule(t, "kustomization.yaml", kustomizationBareLabels, "IAC-239"); got != 1 {
		t.Errorf("IAC-239 fired %d times on a commonLabels block carrying none of the "+
			"app.kubernetes.io labels; want 1", got)
	}
	if got := countRule(t, "kustomization.yaml", kustomizationStandardLabels, "IAC-239"); got != 0 {
		t.Errorf("IAC-239 fired %d times on a commonLabels block that declares the "+
			"standard labels; the rule says they are MISSING", got)
	}
}

// TestEveryFamilyBuilderReadsTheAbsenceFields is the guard for the defect that
// made this conversion necessary to discover.
//
// rules_ansible.go, rules_kustomize.go and rules_serverless.go each declared
// their rules as []iacRule and then hand-rolled the conversion to rules.Rule,
// setting MatcherType to "regex" unconditionally and never reading
// absenceAnchor, extraMetadata or retires. An absence rule declared in one of
// those files would have loaded with an empty pattern and matched nothing —
// indistinguishable from a rule that ran and found nothing. All three now call
// iacRule.toRule().
func TestEveryFamilyBuilderReadsTheAbsenceFields(t *testing.T) {
	for _, tc := range []struct{ rule, wantMatcher string }{
		{"IAC-211", "absence"}, // rules_ansible.go
		{"IAC-239", "absence"}, // rules_kustomize.go
	} {
		r, ok := NewAnalyzer().Rules().ByID(tc.rule)
		if !ok {
			t.Fatalf("%s not found", tc.rule)
		}
		if r.MatcherType != tc.wantMatcher {
			t.Errorf("%s has matcher_type %q, want %q — its family builder is not reading "+
				"the absence fields", tc.rule, r.MatcherType, tc.wantMatcher)
		}
		if r.AbsenceAnchor == "" || r.AbsenceProperty == "" {
			t.Errorf("%s reached the rule set with an empty absence configuration", tc.rule)
		}
	}
	// And the retirement, which the same builders also dropped.
	r, _ := NewAnalyzer().Rules().ByID("IAC-211")
	if len(r.Retires) == 0 {
		t.Error("IAC-211 reached the rule set with no Retires; the family builder dropped it")
	}
}
