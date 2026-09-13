package iac

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
	"github.com/nox-hq/nox/core/rules/structural"
	"gopkg.in/yaml.v3"
)

// IAC-200 asks whether a TASK handling a secret sets `no_log`, and a task is
// not something a regex can identify.
//
// It shipped with `(?i)(?:password|secret|token|key)\s*:(?!.*no_log)` — a
// negative lookahead RE2 does not implement, so it never compiled and never
// fired. Two attempts to express it with the absence matcher failed for
// instructive reasons, and both are why this is a parse:
//
//   - Anchored on the sensitive KEY, the span is the block that key sits in.
//     `no_log` is a sibling of the MODULE, so from a `password:` nested inside
//     `mysql_user:` it is two levels up and outside any such span. Measured: a
//     task that correctly sets `no_log: true` was reported anyway.
//   - Anchored on any sequence item, the span is right but the ANCHOR is not:
//     `- hosts: all` is a play, and a play's block contains every task in it,
//     so one finding swallowed the whole file and duplicated the tasks inside.
//     Requiring the item to be indented would have excluded a task FILE, whose
//     tasks sit at column zero.
//
// A task is a sequence item under `tasks:`, `pre_tasks:`, `post_tasks:`,
// `handlers:`, `block:`, `rescue:` or `always:` — or, in a task file, at the
// document's top level. That is a shape, and reading it is what the structural
// parser is for.

// noLogRuleID is the rule this file reports, keeping IAC-200's ID: baselines
// hash it and waivers name it.
const noLogRuleID = "IAC-200"

// noLogRule is registered for its metadata; the analyzer evaluates it by
// parsing. See the `catalog` field on Analyzer.
func noLogRule() *rules.Rule {
	return &rules.Rule{
		ID:          noLogRuleID,
		Version:     "2.0",
		Description: "Ansible task handles a literal secret without no_log",
		Severity:    findings.SeverityMedium,
		Confidence:  findings.ConfidenceHigh,
		Tags:        []string{"iac", "ansible", "logging"},
		Metadata:    map[string]string{"cwe": "CWE-532"},
		Remediation: "Set `no_log: true` on the task. Ansible prints a task's arguments on failure and under -v, so a secret passed to a module reaches the log, the console and any CI artifact that captures them. Moving the value into Vault is the other half; no_log is what stops it being printed either way.",
		References:  []string{"https://cwe.mitre.org/data/definitions/532.html"},
	}
}

// sensitiveLiteral matches a key that names a secret and carries a LITERAL
// value.
//
// The key must END in a sensitive word, so `accept_hostkey` — a "key" suffix
// inside an ordinary word — does not qualify. It must carry a value, so
// `rpm_key:` opening a block does not. Bare `key` is absent from the list
// because it produced four of six false positives on
// geerlingguy/ansible-for-devops, including
// `key: "https://…/RPM-GPG-KEY-remi2018"`, a PUBLIC key. And `{`/`$` values are
// excluded for the reason IAC-225 excludes them: `"{{ vault_db_password }}"` is
// the fix rather than the finding.
var sensitiveLiteral = regexp.MustCompile(`(?i)^(?:[a-z0-9]+_)*(?:password|passwd|secret|api_key|access_key|secret_key|private_key|auth_token|token)$`)

// scanAnsibleNoLog reports every Ansible task that passes a literal secret to a
// module without setting no_log.
func scanAnsibleNoLog(path string, content []byte) []findings.Finding {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yml", ".yaml":
	default:
		return nil
	}
	if !isAnsibleDocument(path, content) {
		return nil
	}
	docs, err := structural.Parse(content)
	if err != nil {
		return nil
	}
	var out []findings.Finding
	for _, doc := range docs {
		root := doc
		if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
			root = root.Content[0]
		}
		for _, task := range ansibleTaskNodes(root) {
			key := taskSecretLiteral(task)
			if key == nil {
				continue
			}
			if mappingValue(task, "no_log") != nil {
				continue
			}
			out = append(out, findings.Finding{
				RuleID:     noLogRuleID,
				Severity:   findings.SeverityMedium,
				Confidence: findings.ConfidenceHigh,
				Message: fmt.Sprintf("Ansible task passes a literal %s to a module and does not set no_log",
					key.Value),
				Location: findings.Location{
					FilePath: path, StartLine: key.Line, EndLine: key.Line,
					StartColumn: key.Column, EndColumn: key.Column + len(key.Value),
				},
				Metadata: map[string]string{"cwe": "CWE-532", "parameter": key.Value},
			})
		}
	}
	return out
}

// ansibleTaskNodes returns every task mapping in a document.
//
// A playbook is a sequence of plays and the tasks are under a play's `tasks:`,
// `pre_tasks:`, `post_tasks:` or `handlers:`; a task file is a sequence of
// tasks directly; and `block:`/`rescue:`/`always:` nest tasks inside a task.
// A play is told from a task by the keys it holds — a play has `hosts:`.
func ansibleTaskNodes(root *yaml.Node) []*yaml.Node {
	var out []*yaml.Node
	if root == nil || root.Kind != yaml.SequenceNode {
		return nil
	}
	for _, item := range root.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		if mappingValue(item, "hosts") != nil {
			// A play. Its tasks are in its task-holding keys.
			for _, k := range []string{"tasks", "pre_tasks", "post_tasks", "handlers"} {
				out = append(out, ansibleTaskNodes(mappingValue(item, k))...)
			}
			continue
		}
		out = append(out, item)
		// block/rescue/always hold tasks inside a task.
		for _, k := range []string{"block", "rescue", "always"} {
			out = append(out, ansibleTaskNodes(mappingValue(item, k))...)
		}
	}
	return out
}

// taskSecretLiteral returns the KEY node of a literal secret this task passes
// to a module, or nil.
//
// The search is a full walk of the task, because module arguments nest: a
// docker_container's password sits at task → docker_container → env →
// MYSQL_ROOT_PASSWORD, three levels down, and a depth limit of two missed four
// of the five real findings in geerlingguy/ansible-for-devops.
//
// It returns the FIRST one, so a task is reported once however many secrets it
// passes and however a `with_items` list repeats them — one task, one thing to
// fix. The nested task lists are skipped: block/rescue/always hold tasks of
// their own, and ansibleTaskNodes already visits them.
func taskSecretLiteral(task *yaml.Node) *yaml.Node {
	if task == nil {
		return nil
	}
	switch task.Kind {
	case yaml.SequenceNode:
		for _, c := range task.Content {
			if k := taskSecretLiteral(c); k != nil {
				return k
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(task.Content); i += 2 {
			k, v := task.Content[i], task.Content[i+1]
			switch k.Value {
			case "block", "rescue", "always":
				continue
			}
			if isLiteralSecretPair(k, v) {
				return k
			}
			if nested := taskSecretLiteral(v); nested != nil {
				return nested
			}
		}
	}
	return nil
}

// isLiteralSecretPair reports whether a key names a secret and its value is a
// literal rather than a template or a variable reference.
func isLiteralSecretPair(k, v *yaml.Node) bool {
	if v.Kind != yaml.ScalarNode || !sensitiveLiteral.MatchString(k.Value) {
		return false
	}
	val := strings.TrimSpace(v.Value)
	if val == "" || strings.Contains(val, "{{") || strings.HasPrefix(val, "$") {
		return false
	}
	return !nonSecretScalars[strings.ToLower(val)]
}
