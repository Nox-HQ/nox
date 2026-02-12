package iac

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// ---------------------------------------------------------------------------
// Ansible rule count
// ---------------------------------------------------------------------------

func TestAnsibleRules_Count(t *testing.T) {
	rules := builtinAnsibleRules()
	if got := len(rules); got != 45 {
		t.Errorf("expected 45 Ansible rules, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// IAC-186: become: true without become_user
// ---------------------------------------------------------------------------

func TestDetect_AnsibleBecomeWithoutUser(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`---
- hosts: webservers
  become: true
  tasks:
    - name: Install nginx
      apt:
        name: nginx
        state: present
`)

	results, err := a.ScanFile("playbook.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-186" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-186 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-187: become_user: root
// ---------------------------------------------------------------------------

func TestDetect_AnsibleBecomeUserRoot(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`---
- hosts: all
  become: true
  become_user: root
  tasks:
    - name: Restart service
      service:
        name: httpd
        state: restarted
`)

	results, err := a.ScanFile("playbook.yaml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-187" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-187 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-190: ansible_become_pass in plaintext (critical)
// ---------------------------------------------------------------------------

func TestDetect_AnsibleBecomePassPlaintext(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`---
all:
  hosts:
    web1:
      ansible_host: 192.168.1.10
      ansible_become_pass: secret123
`)

	results, err := a.ScanFile("playbook.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-190" {
			found = true
			if f.Severity != findings.SeverityCritical {
				t.Errorf("expected severity critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-190 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-193: shell module usage
// ---------------------------------------------------------------------------

func TestDetect_AnsibleShellModule(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`---
- hosts: all
  tasks:
    - name: Remove temp files
      shell: rm -rf /tmp/*
`)

	results, err := a.ScanFile("tasks.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-193" {
			found = true
			if f.Severity != findings.SeverityMedium {
				t.Errorf("expected severity medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-193 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-199: no_log: false
// ---------------------------------------------------------------------------

func TestDetect_AnsibleNoLogFalse(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`---
- hosts: all
  tasks:
    - name: Show debug info
      debug:
        msg: "some output"
      no_log: false
`)

	results, err := a.ScanFile("playbook.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-199" {
			found = true
			if f.Severity != findings.SeverityMedium {
				t.Errorf("expected severity medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-199 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-202: failed_when: false
// ---------------------------------------------------------------------------

func TestDetect_AnsibleFailedWhenFalse(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`---
- hosts: all
  tasks:
    - name: Try something
      command: /opt/bin/check
      failed_when: false
`)

	results, err := a.ScanFile("playbook.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-202" {
			found = true
			if f.Severity != findings.SeverityMedium {
				t.Errorf("expected severity medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-202 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-208: Sensitive file with overly permissive mode
// ---------------------------------------------------------------------------

func TestDetect_AnsibleSensitiveFilePermissiveMode(t *testing.T) {
	a := NewAnalyzer()
	// Pattern: (?i)(?:private_key|\.pem|\.key|credentials).*mode:\s*['"]?0?[67][0-9][0-9]
	// Requires the sensitive filename reference and mode: on the same line.
	content := []byte(`---
- hosts: all
  tasks:
    - name: Deploy key
      file: path=/etc/ssl/server.key mode: 0644
`)

	results, err := a.ScanFile("playbook.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-208" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-208 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-216: UFW allows SSH from any source
// ---------------------------------------------------------------------------

func TestDetect_AnsibleUFWAllowSSH(t *testing.T) {
	a := NewAnalyzer()
	// Pattern: (?i)ufw:.*rule:\s*['"]?allow['"]?.*port:\s*['"]?22['"]?
	// Requires ufw:, rule:, and port: with colons all on the same line.
	content := []byte(`---
- hosts: all
  tasks:
    - name: Allow SSH
      ufw: rule: allow port: 22
`)

	results, err := a.ScanFile("playbook.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-216" {
			found = true
			if f.Severity != findings.SeverityMedium {
				t.Errorf("expected severity medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-216 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-201: ignore_errors: yes
// ---------------------------------------------------------------------------

func TestDetect_AnsibleIgnoreErrors(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`---
- hosts: all
  tasks:
    - name: Risky task
      command: /opt/check
      ignore_errors: yes
`)

	results, err := a.ScanFile("playbook.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-201" {
			found = true
			if f.Severity != findings.SeverityMedium {
				t.Errorf("expected severity medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-201 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-203: validate_certs: false
// ---------------------------------------------------------------------------

func TestDetect_AnsibleValidateCertsFalse(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`---
- hosts: all
  tasks:
    - name: Fetch resource
      uri:
        url: https://internal.example.com/data
        validate_certs: false
`)

	results, err := a.ScanFile("playbook.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-203" {
			found = true
			if f.Severity != findings.SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-203 to be detected")
	}
}

// ---------------------------------------------------------------------------
// IAC-225: Hardcoded password
// ---------------------------------------------------------------------------

func TestDetect_AnsibleHardcodedPassword(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`---
- hosts: all
  vars:
    db_password: "mysecretpassword"
  tasks:
    - name: Configure DB
      template:
        src: db.conf.j2
        dest: /etc/db.conf
`)

	results, err := a.ScanFile("playbook.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range results {
		if f.RuleID == "IAC-225" {
			found = true
			if f.Severity != findings.SeverityCritical {
				t.Errorf("expected severity critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected IAC-225 to be detected")
	}
}

// ---------------------------------------------------------------------------
// No false positives on clean Ansible content
// ---------------------------------------------------------------------------

func TestNoFalsePositives_CleanAnsible(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`---
- hosts: webservers
  become: false
  tasks:
    - name: Copy config
      copy:
        src: app.conf
        dest: /etc/app/app.conf
        mode: '0644'
    - name: Restart app
      service:
        name: myapp
        state: restarted
`)

	results, err := a.ScanFile("playbook.yml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Filter to only Ansible rules (IAC-186 to IAC-230).
	for _, f := range results {
		if f.RuleID >= "IAC-186" && f.RuleID <= "IAC-230" {
			t.Errorf("unexpected Ansible finding %s on clean content", f.RuleID)
		}
	}
}
