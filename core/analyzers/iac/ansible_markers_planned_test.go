package iac

import (
	"regexp"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/rules"
)

// The Ansible markers run on every YAML file the IaC analyzer reads. As
// line-anchored patterns they were full regexp scans, 1.8 s of a 58 s crewAI
// profile; each must keep its literal-prefix plan and answer as regexp does.
func TestAnsibleMarkersArePlannedAndExact(t *testing.T) {
	markers := map[string]*rules.PlannedRegexp{
		"key":   ansibleKeyMarkers,
		"token": ansibleTokenMarkers,
		"task":  ansibleTaskFile,
	}
	corpus := []string{
		"", "- hosts: all\n  tasks:\n", "  - name: x\n", "- name: install\n",
		"jobs:\n  build:\n    steps:\n      - name: checkout\n", "Roles:\n  - Admin\n",
		"x: 1\nbecome: true\n", "x: 1 hosts: no\n", "\t-\tinclude_tasks : a.yml",
		"msg: '{{ ansible_hostname }}'", "community.general.ufw:", "kind: Deployment\n",
		"ſerial: 1\n", "\xffroles:\n", strings.Repeat("name: x\n", 40) + "- name: y",
	}
	for name, p := range markers {
		if !p.HasPlan() {
			t.Errorf("%s: pattern %q has no literal-prefix plan", name, p)
		}
		re := regexp.MustCompile(p.String())
		for _, c := range corpus {
			if got, want := p.Match([]byte(c)), re.MatchString(c); got != want {
				t.Errorf("%s on %q: %v, regexp says %v", name, c, got, want)
			}
		}
	}
}
