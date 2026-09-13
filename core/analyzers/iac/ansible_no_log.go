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
//
// # What the rule asserts
//
// A task HANDLES A SECRET and does not suppress logging, so the secret reaches
// the log, the console, and any CI artifact that captures them.
//
// A task handles a secret when either end of the flow says so:
//
//   - the DESTINATION is a module parameter whose name ends in a sensitive word
//     — `mysql_user: {password: …}`. Whatever flows into a parameter called
//     `password` is a password; that is the module's own vocabulary, not a
//     guess about the value.
//   - the SOURCE is a variable whose name ends in a sensitive word —
//     `command: "pg_dump --password {{ vault_db_password }}"`. The destination
//     is ordinary and the value is still a secret.
//
// Neither half is "a template is a secret". `msg: "{{ item.name }}"` is a
// template, references nothing sensitive and goes to an ordinary parameter, and
// it stays clean. The first version of this rule required a LITERAL value,
// which was a safe narrowing and lost the distinctly Ansible risk: the reason
// `no_log` exists is that Ansible prints the RESOLVED arguments, so a vaulted
// secret is exactly the case that leaks.

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

// sensitiveVariable matches a Jinja expression that references a variable whose
// name ENDS in a sensitive word: `{{ vault_db_password }}`, `{{ item.password }}`,
// `{{ lookup('env', 'DB_PASSWORD') }}`, `{{ db_password | default(”) }}`.
//
// Ending is what keeps it honest, exactly as it does for a key. `token_bucket_size`
// and `password_file` are not secrets and do not match, because the sensitive
// word is followed by more identifier. `ssh_public_key` does not match either:
// bare `key` is absent from the list, and `private_key` is not `public_key`.
var sensitiveVariable = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_])(?:[a-z0-9]+_)*(?:password|passwd|secret|api_key|access_key|secret_key|private_key|auth_token|token)(?:$|[^a-z0-9_])`)

// jinjaExpr captures the inside of a `{{ … }}`.
var jinjaExpr = regexp.MustCompile(`\{\{([^}]*)\}\}`)

// valueIsSecret reports whether a scalar value is a secret, and says which half
// of the proposition made it one.
func valueIsSecret(keyIsSensitive bool, raw string) (why string, ok bool) {
	val := strings.TrimSpace(raw)
	if val == "" || nonSecretScalars[strings.ToLower(val)] {
		return "", false
	}
	if exprs := jinjaExpr.FindAllStringSubmatch(val, -1); len(exprs) > 0 {
		for _, e := range exprs {
			if sensitiveVariable.MatchString(e[1]) {
				return "a secret-named variable", true
			}
		}
		// A template going to a secret-named parameter still resolves to a
		// secret at run time, which is what gets printed.
		if keyIsSensitive {
			return "a templated value", true
		}
		return "", false
	}
	if !keyIsSensitive {
		return "", false
	}
	if strings.HasPrefix(val, "$") {
		// A shell/environment reference, not a value this document holds.
		return "", false
	}
	return "a literal value", true
}

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
		for _, task := range ansibleTaskNodes(root, false) {
			key, why := taskSecret(task.node)
			if key == nil {
				continue
			}
			if task.inheritedNoLog || noLogIsSet(task.node) {
				continue
			}
			out = append(out, findings.Finding{
				RuleID:     noLogRuleID,
				Severity:   findings.SeverityMedium,
				Confidence: findings.ConfidenceHigh,
				Message: fmt.Sprintf("Ansible task passes %s to %q and does not set no_log, "+
					"so Ansible prints the resolved value", why, key.Value),
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

// ansibleTask is one task and whether logging is already suppressed for it by
// something above.
type ansibleTask struct {
	node *yaml.Node
	// inheritedNoLog is true when a play or an enclosing block sets no_log.
	// Ansible propagates no_log down from the play and from a block to the
	// tasks inside, so a playbook that sets it once at the top has covered
	// every task in it, and reporting those would be telling an operator who
	// did the right thing that they did not.
	inheritedNoLog bool
}

// ansibleTaskNodes returns every task in a document, with the no_log it
// inherits.
//
// A playbook is a sequence of plays and the tasks are under a play's `tasks:`,
// `pre_tasks:`, `post_tasks:` or `handlers:`; a task file is a sequence of
// tasks directly; and `block:`/`rescue:`/`always:` nest tasks inside a task.
// A play is told from a task by the keys it holds — a play has `hosts:`.
func ansibleTaskNodes(root *yaml.Node, inherited bool) []ansibleTask {
	var out []ansibleTask
	if root == nil || root.Kind != yaml.SequenceNode {
		return nil
	}
	for _, item := range root.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		if mappingValue(item, "hosts") != nil {
			// A play. Its no_log covers every task in it.
			playNoLog := inherited || noLogIsSet(item)
			for _, k := range []string{"tasks", "pre_tasks", "post_tasks", "handlers"} {
				out = append(out, ansibleTaskNodes(mappingValue(item, k), playNoLog)...)
			}
			continue
		}
		out = append(out, ansibleTask{node: item, inheritedNoLog: inherited})
		// block/rescue/always hold tasks inside a task, and a no_log on the
		// task that carries the block covers them.
		blockNoLog := inherited || noLogIsSet(item)
		for _, k := range []string{"block", "rescue", "always"} {
			out = append(out, ansibleTaskNodes(mappingValue(item, k), blockNoLog)...)
		}
	}
	return out
}

// noLogIsSet reports whether a play, block or task suppresses logging.
//
// Presence is enough: `no_log: "{{ hide_secrets }}"` is a deliberate decision
// whose value this cannot resolve, and treating an unresolvable one as "not
// set" would report the operator for having thought about it.
func noLogIsSet(n *yaml.Node) bool {
	v := mappingValue(n, "no_log")
	if v == nil {
		return false
	}
	return !nonSecretScalars[strings.ToLower(strings.TrimSpace(v.Value))] ||
		strings.EqualFold(strings.TrimSpace(v.Value), "true") ||
		strings.EqualFold(strings.TrimSpace(v.Value), "yes")
}

// taskSecret returns the KEY node of a secret this task handles, and which half
// of the proposition made it one.
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
func taskSecret(task *yaml.Node) (key *yaml.Node, why string) {
	if task == nil {
		return nil, ""
	}
	switch task.Kind {
	case yaml.SequenceNode:
		for _, c := range task.Content {
			if k, why := taskSecret(c); k != nil {
				return k, why
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(task.Content); i += 2 {
			k, v := task.Content[i], task.Content[i+1]
			switch k.Value {
			case "block", "rescue", "always":
				continue
			case "no_log", "when", "name", "tags", "register":
				// Control keys, not module arguments. `when:` in particular
				// often mentions a variable without passing it anywhere.
				continue
			}
			if v.Kind == yaml.ScalarNode {
				if why, ok := valueIsSecret(sensitiveLiteral.MatchString(k.Value), v.Value); ok {
					return k, why
				}
				continue
			}
			if nested, why := taskSecret(v); nested != nil {
				return nested, why
			}
		}
	}
	return nil, ""
}
