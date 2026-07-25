package iac

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// Every Ansible rule is scoped to `*.yml`/`*.yaml`, which is every YAML file
// in the repository — including GitHub Actions workflows and composite
// actions. So `shell: bash`, which a composite action step is REQUIRED to
// declare, matched IAC-193 "Ansible task uses shell module".
//
// This is the context-confusion class: a pattern firing where it cannot mean
// what the rule assumes. A GitHub Actions file is not an Ansible playbook, so
// the finding is categorically wrong rather than merely lower severity — the
// existing GHA pass downgrades, which is the wrong remedy here. nox's own tree
// carried five `nox:ignore IAC-193 -- composite-style step, not Ansible`
// waivers papering over exactly this.
//
// Composite actions matter as much as workflows: four of those five waivers
// were on `action.yml` files, which the workflows-only path prefix never
// covered.
func TestApplyGHAContext_AnsibleRulesDroppedOnGitHubActionsFiles(t *testing.T) {
	workflow := []byte("name: CI\non: [push]\njobs:\n  b:\n    steps:\n      - shell: bash\n        run: go test ./...\n")
	composite := []byte("name: act\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo hi\n")

	cases := []struct {
		name, path string
		content    []byte
	}{
		{"workflow", ".github/workflows/ci.yml", workflow},
		{"composite action at root", "action.yml", composite},
		{"composite action nested", "actions/remediate/action.yml", composite},
		{"composite action .yaml", "actions/x/action.yaml", composite},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := []findings.Finding{
				mkFinding("IAC-193", tc.path),
				// A non-Ansible IaC rule on the same file must survive: this
				// pass may only remove findings that cannot apply, not quietly
				// prune the workflow's real findings.
				mkFinding("IAC-314", tc.path),
			}
			out := ApplyGHAContext(in, map[string][]byte{tc.path: tc.content})

			for _, f := range out {
				if f.RuleID == "IAC-193" {
					t.Errorf("IAC-193 (Ansible shell module) survived on GitHub Actions file %s", tc.path)
				}
			}
			var keptOther bool
			for _, f := range out {
				if f.RuleID == "IAC-314" {
					keptOther = true
				}
			}
			if !keptOther {
				t.Errorf("a non-Ansible finding was dropped from %s; only Ansible rules may be removed", tc.path)
			}
		})
	}
}

// The converse, and the reason this is a targeted drop rather than a blanket
// one: a real Ansible playbook must still be flagged. A playbook is an
// ordinary .yml file with no GitHub Actions shape, so nothing about it should
// reach the GHA pass.
func TestApplyGHAContext_AnsibleRulesSurviveOnPlaybooks(t *testing.T) {
	playbook := []byte("- hosts: all\n  tasks:\n    - name: run it\n      shell: /usr/bin/thing --flag\n")
	paths := []string{"playbook.yml", "ansible/site.yaml", "roles/web/tasks/main.yml"}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			in := []findings.Finding{mkFinding("IAC-193", p)}
			out := ApplyGHAContext(in, map[string][]byte{p: playbook})
			if len(out) != 1 || out[0].RuleID != "IAC-193" {
				t.Errorf("IAC-193 was dropped from Ansible playbook %s: %+v", p, out)
			}
		})
	}
}

func mkFinding(ruleID, path string) findings.Finding {
	return findings.NewFinding(
		ruleID, findings.SeverityMedium, findings.ConfidenceLow,
		findings.Location{FilePath: path, StartLine: 1, EndLine: 1},
		"test finding",
	)
}
