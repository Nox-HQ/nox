package iac

import (
	"regexp"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/rules"
)

// Eight IaC rules spelled an absence with a negative lookahead. RE2 has no
// lookahead, so every one of them failed to compile — and RegexMatcher.compile
// returns the error while Match answers nil, so they loaded, listed in
// `nox rules`, ran on every file and matched nothing.
//
// They were KNOWN: pattern_compile_test.go tracked them, with a reason each,
// after 57 of an original 65 had been converted. The reason given was that they
// needed per-item scoping no span modelled, and that "leaving them dead is
// safer than shipping a noisy approximation". That was right, and it was tested
// against — three of the eight turned out to be unfixable for the reasons given
// and are removed; the other five have working detection now.

// TestNoIaCRulePatternIsUncompilable is the guard, and it is absolute: the
// tracked set is empty.
func TestNoIaCRulePatternIsUncompilable(t *testing.T) {
	for _, r := range builtinIaCRules() {
		for label, p := range map[string]string{
			"pattern": r.Pattern, "absence_anchor": r.AbsenceAnchor,
			"absence_property": r.AbsenceProperty, "absence_require": r.AbsenceRequire,
		} {
			if p == "" {
				continue
			}
			if _, err := regexp.Compile(p); err != nil {
				t.Errorf("%s %s does not compile (%v); the matcher gives up silently and "+
					"the rule can never fire", r.ID, label, err)
			}
		}
	}
	if len(knownUncompilableIaCRules) != 0 {
		t.Errorf("knownUncompilableIaCRules must stay empty, has %d", len(knownUncompilableIaCRules))
	}
}

// TestCheckCoherenceRejectsAnUncompilablePattern. The guard above is the second
// of two: CheckCoherence refuses the rule at load, which is what makes the
// class structurally impossible rather than merely tested. The loader calls it,
// so a custom rule with a bad pattern is a validation error rather than a rule
// that silently found nothing.
func TestCheckCoherenceRejectsAnUncompilablePattern(t *testing.T) {
	r := &rules.Rule{
		ID: "TEST-001", MatcherType: "regex", Pattern: `(?i)foo(?!bar)`,
		Severity: "high", Confidence: "high",
	}
	err := r.CheckCoherence()
	if err == nil {
		t.Fatal("CheckCoherence accepted a pattern that does not compile")
	}
	if !strings.Contains(err.Error(), "never fire") {
		t.Errorf("the error does not say what the consequence is: %v", err)
	}
}

// TestTheThreeUnfixableOnesAreGone. Each was removed because its claim cannot
// be established from the document, not because it was inconvenient — so the
// reason is asserted here rather than only in a commit message.
func TestTheThreeUnfixableOnesAreGone(t *testing.T) {
	set := NewAnalyzer().Rules()
	for id, why := range map[string]string{
		"IAC-159": "branch protection is a repository setting; a workflow file cannot contain " +
			"required_status_checks, so the absence it looked for is universal",
		"IAC-170": "a Terraform `backend \"s3\"` block has no `versioning` argument; versioning " +
			"is a property of the bucket resource",
		"IAC-173": "a blanket AWS tags check needs a per-type taggability table, and without " +
			"one it fires on resource types that cannot be tagged",
	} {
		if _, ok := set.ByID(id); ok {
			t.Errorf("%s is back. %s", id, why)
		}
	}
}

// TestIAC155NeedsNoEnvironmentAnywhere. The span is the file: a
// `workflow_dispatch:` trigger and the `environment:` that gates it live in
// different places — the trigger under `on:`, the environment on a job — so the
// question the rule can honestly ask is whether the workflow declares one at
// all. Erring toward silence when it does is the safe direction.
func TestIAC155NeedsNoEnvironmentAnywhere(t *testing.T) {
	const ungated = `on:
  workflow_dispatch:
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: make deploy
`
	const gated = `on:
  workflow_dispatch:
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - run: make deploy
`
	if n := countRule(t, "release.yml", ungated, "IAC-155"); n != 1 {
		t.Errorf("IAC-155 fired %d times on a manual trigger with no environment anywhere; want 1", n)
	}
	if n := countRule(t, "release.yml", gated, "IAC-155"); n != 0 {
		t.Errorf("IAC-155 fired %d times on a workflow that gates its deploy job behind an "+
			"environment; want 0", n)
	}
}

// TestIAC200ReportsOnlySensitiveLiterals is the measurement that tightened it.
// Before the anchor required the key to END in a sensitive word, to carry a
// VALUE, and not to be a bare `key`, 6 of 11 findings on
// geerlingguy/ansible-for-devops were false.
func TestIAC200ReportsOnlySensitiveLiterals(t *testing.T) {
	const playbook = `- hosts: all
  tasks:
    - name: real leak
      mysql_user:
        password: hunter2
    - name: logged deliberately
      mysql_user:
        password: hunter2
      no_log: true
    - name: git checkout
      git:
        accept_hostkey: true
    - name: import a public gpg key
      rpm_key:
        key: "https://rpms.remirepo.net/RPM-GPG-KEY-remi2018"
    - name: from the vault
      mysql_user:
        password: "{{ vault_db_password }}"
`
	if n := countRule(t, "playbook.yml", playbook, "IAC-200"); n != 1 {
		t.Errorf("IAC-200 fired %d times; want 1 — the hardcoded password with no no_log. "+
			"`accept_hostkey` is a key SUFFIX inside a word, `rpm_key:` opens a block, the "+
			"GPG key is public and the vault value is the fix rather than the finding", n)
	}
}

// TestTheAnsibleMarkersAreKeysNotSubstrings is a regression guard for a defect
// this work introduced and the measurement caught.
//
// Matching `tasks:` anywhere admitted a CloudFormation template whose
// Description reads "This template accomplishes the following tasks: (1) …" —
// prose, in a field. Matching case-insensitively admitted another whose IAM
// resource declares `Roles:`. Ansible keys are lower-case and they are keys, so
// the marker is both.
func TestTheAnsibleMarkersAreKeysNotSubstrings(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"tasks in prose", "AWSTemplateFormatVersion: \"2010-09-09\"\n" +
			"Description: 'This template accomplishes the following tasks: (1) applies a tag.'\n" +
			"Resources:\n  Thing:\n    Type: AWS::S3::Bucket\n"},
		{"capitalised Roles", "AWSTemplateFormatVersion: \"2010-09-09\"\n" +
			"Resources:\n  Profile:\n    Type: AWS::IAM::InstanceProfile\n" +
			"    Properties:\n      Roles:\n        - !Ref Role\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if isAnsibleDocument("template.yaml", []byte(tc.body)) {
				t.Error("a CloudFormation template was admitted to the Ansible family")
			}
		})
	}
	// The control: a real playbook is still admitted, or the guard above would
	// pass by excluding everything.
	if !isAnsibleDocument("playbook.yml", []byte("- hosts: all\n  become: true\n  tasks: []\n")) {
		t.Error("a real playbook is no longer recognised")
	}
}

// TestIAC200IsPerTaskNotPerPlay. A play's block contains every task in it, so
// anchoring on any sequence item made one finding swallow the file and
// duplicate the tasks inside. A play is told from a task by `hosts:`.
func TestIAC200IsPerTaskNotPerPlay(t *testing.T) {
	const playbook = `- hosts: all
  tasks:
    - name: one
      mysql_user:
        password: hunter2
    - name: two
      docker_container:
        env:
          MYSQL_ROOT_PASSWORD: root
`
	fs := scanAnsibleNoLog("playbook.yml", []byte(playbook))
	if len(fs) != 2 {
		t.Fatalf("reported %d findings; want 2 — one per task, and none for the play "+
			"that contains them", len(fs))
	}
	// The second is three levels down: task -> docker_container -> env -> KEY.
	// A depth limit of two missed four of the five real findings in
	// geerlingguy/ansible-for-devops.
	var deep bool
	for _, f := range fs {
		if f.Metadata["parameter"] == "MYSQL_ROOT_PASSWORD" {
			deep = true
		}
	}
	if !deep {
		t.Error("a secret nested inside a module's env block was not found")
	}
}

// TestOneTaskIsOneFinding. A task passing several secrets, or repeating one
// through a loop, is one thing to fix.
func TestOneTaskIsOneFinding(t *testing.T) {
	const many = `- name: several
  docker_container:
    env:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_PASSWORD: flask
      APP_SECRET: s3cr3t
`
	if n := len(scanAnsibleNoLog("tasks.yml", []byte(many))); n != 1 {
		t.Errorf("reported %d findings for one task carrying three secrets; want 1", n)
	}
}

// TestNoLogSilencesTheTask is the direction that matters most: a user who did
// the right thing must not be told they did not. Anchoring on the sensitive KEY
// got this wrong, because `no_log` is a sibling of the MODULE.
func TestNoLogSilencesTheTask(t *testing.T) {
	const logged = `- name: logged deliberately
  mysql_user:
    password: hunter2
  no_log: true
`
	if n := len(scanAnsibleNoLog("tasks.yml", []byte(logged))); n != 0 {
		t.Errorf("reported %d findings on a task that sets no_log: true", n)
	}
}
