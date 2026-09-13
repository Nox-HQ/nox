package iac

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// A filename is a discovery hint. It is not evidence that a rule applies.
//
// The Serverless Framework family scoped itself with
//
//	{"serverless.yml", "serverless.yaml", "serverless.ts", "*.yml", "*.yaml"}
//
// where the last two entries make the first three meaningless: every rule in
// the family applied to every YAML file in any repository. Measured 2026-09-12
// on MacPaw/OpenAI@0.5.1, a Swift package, IAC-254 ("Serverless environment
// variable with hardcoded secret", CRITICAL) fired 268 times on openapi.yaml
// against Ruby documentation samples reading
//
//	openai = OpenAI::Client.new(api_key: "My API Key")
//
// and told the reader to use ${ssm:/path/to/secret} in a file that has no such
// concept.
//
// Three independent things had to line up, and removing any one of them would
// have hidden rather than fixed it: the *.yaml catch-all made every YAML file
// eligible; the rule's keywords gate at FILE level, so one "environment"
// anywhere in a 2.8MB specification admitted the whole file; and the pattern
// matches any `api_key:` assignment. Narrowing the glob to serverless*.yml
// would have left the family able to fire on serverless-named files that are
// not manifests, and left the other IaC families with the same shape untouched.
//
// So applicability is decided by the document, once, for the family: a
// Serverless rule fires only where the document IS a Serverless manifest.

// serverlessFamilyTag marks a rule as belonging to the Serverless Framework
// family. Keying on the tag rather than on an ID list is what makes this
// structural: a rule added to the family tomorrow inherits the gate without
// anyone remembering to add it anywhere.
const serverlessFamilyTag = "serverless"

// isServerlessManifest reports whether content is a Serverless Framework
// manifest.
//
// The Framework requires both `service` and `provider`; a document carrying
// neither is not one, whatever it is called. The check is deliberately shallow
// — it reads top-level keys, not the whole schema — because its job is to
// separate "this is a serverless.yml" from "this is an OpenAPI spec", not to
// validate a configuration.
//
// It errs toward applying the rules: a manifest that somehow omits `provider`
// still counts on the strength of `service`, because a missed finding costs
// more than a false one and the two keys together are what the format
// guarantees, not what every file in the wild contains.
func isServerlessManifest(path string, content []byte) bool {
	// A TypeScript config expresses the same keys as object properties rather
	// than as YAML, so the top-level-column rule does not apply to it.
	topLevelOnly := true
	if ext := strings.ToLower(filepath.Ext(path)); ext == ".ts" || ext == ".js" {
		topLevelOnly = false
	}

	var service, provider bool
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if topLevelOnly && line != trimmed {
			// Indented: a nested key, not a document-level declaration. This is
			// what keeps `provider:` inside some unrelated structure from
			// making an OpenAPI spec look like a manifest.
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "service:"), strings.HasPrefix(trimmed, "service :"):
			service = true
		case strings.HasPrefix(trimmed, "provider:"), strings.HasPrefix(trimmed, "provider :"):
			provider = true
		}
		if service && provider {
			return true
		}
	}
	return service
}

// kustomizeFamilyTag marks a rule as belonging to the Kustomize family, and
// carries the same shape of defect the Serverless family carried:
//
//	{"kustomization.yaml", "kustomization.yml", "*.yaml", "*.yml"}
//
// Measured 2026-09-12 across the rule-diff corpus, 37 of the family's 40
// findings were on documents that are not kustomizations at all: `Count: 1` in
// a CloudFormation ResourceSignal and `InstanceCount: 1` on an EMR cluster
// reported as "Kustomize sets replica count to 1 (no HA)", `replicaCount: 1`
// in a Helm values file reported the same way, `secretNamespace: "default"` in
// a GlusterFS StorageClass reported as "Kustomize deploys to default
// namespace", and `image: ...:latest` in a docker-compose service reported as
// "Kustomize uses latest image tag".
const kustomizeFamilyTag = "kustomize"

// kustomizeOnlyTopLevelKeys are fields that only a kustomization declares at
// the top level.
//
// The ambiguous ones are deliberately absent. `resources`, `labels`, `images`,
// `replicas`, `patches` and `namespace` are all kustomization fields AND
// ordinary keys elsewhere — podinfo's charts/podinfo/values.yaml, a Helm
// values file, declares a top-level `resources:` — so admitting them by name
// would re-open the family onto exactly the documents this gate exists to
// close it against. `openapi` and `components` are absent for the sharper
// reason that they are the top-level keys of an OpenAPI specification, the
// document that produced the Serverless family's 268 findings.
var kustomizeOnlyTopLevelKeys = map[string]bool{
	"bases": true, "patchesStrategicMerge": true, "patchesJson6902": true,
	"configMapGenerator": true, "secretGenerator": true, "generatorOptions": true,
	"namePrefix": true, "nameSuffix": true, "commonLabels": true,
	"commonAnnotations": true, "helmCharts": true, "helmGlobals": true,
	"transformers": true, "buildMetadata": true, "sortOptions": true,
	"crds": true, "configurations": true,
}

// isKustomization reports whether content is a Kustomize kustomization.
//
// Three things can say so, in order of how much they prove:
//
//   - `kind: Kustomization` (or `Component`), or an apiVersion under
//     kustomize.config.k8s.io. All eight kustomizations in the corpus declare
//     both.
//   - a top-level field only a kustomization has.
//   - a top-level `resources:` introducing a LIST. Kustomize's `resources` is
//     a sequence of paths; the `resources:` in a Helm values file or a pod
//     spec is a mapping of limits and requests, and the first character after
//     the key is what separates them. Without this branch a kustomization
//     written before apiVersion/kind were conventional — `resources:` and
//     nothing else — would be missed, and a missed finding costs more than a
//     false one.
//
// One thing is decisive against: a top-level `kind:` naming anything else. A
// StorageClass is a StorageClass whatever else it contains, and that single
// negative is what keeps every Kubernetes manifest in a repository out of the
// family.
//
// The file name is deliberately not consulted, including the canonical
// `kustomization.yaml`. The instruction this gate exists to enforce is that a
// name is a discovery hint, and a gate that exempts the one name the family is
// built around does not enforce it.
func isKustomization(_ string, content []byte) bool {
	// A YAML stream may hold several documents. A kustomization is a single
	// document, but a file that bundles one with its output should still be
	// treated as carrying a kustomization: the gate errs toward applying.
	for _, doc := range splitYAMLDocuments(string(content)) {
		if documentIsKustomization(doc) {
			return true
		}
	}
	return false
}

// splitYAMLDocuments splits a YAML stream on its `---` document separators.
func splitYAMLDocuments(content string) []string {
	var docs []string
	var cur []string
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimRight(line, " \t\r") == "---" {
			docs = append(docs, strings.Join(cur, "\n"))
			cur = nil
			continue
		}
		cur = append(cur, line)
	}
	return append(docs, strings.Join(cur, "\n"))
}

// documentIsKustomization applies the decision to a single YAML document.
func documentIsKustomization(doc string) bool {
	var qualifies bool
	lines := strings.Split(doc, "\n")
	for i, line := range lines {
		key, value, ok := topLevelKey(line)
		if !ok {
			continue
		}
		switch key {
		case "kind":
			if v := unquote(value); v == "Kustomization" || v == "Component" {
				return true
			}
			// Some other Kubernetes resource. Decisive, and returned rather
			// than recorded, because nothing later in the document can make a
			// StorageClass a kustomization.
			if value != "" {
				return false
			}
		case "apiVersion":
			if strings.Contains(value, "kustomize.config.k8s.io") {
				return true
			}
		case "resources":
			// A sequence, not a mapping: `resources:` followed by `- path`.
			if value == "" && nextLineIsSequenceItem(lines[i+1:]) {
				qualifies = true
			}
		default:
			if kustomizeOnlyTopLevelKeys[key] {
				qualifies = true
			}
		}
	}
	return qualifies
}

// nextLineIsSequenceItem reports whether the next meaningful line opens a YAML
// sequence.
func nextLineIsSequenceItem(rest []string) bool {
	for _, line := range rest {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		return strings.HasPrefix(trimmed, "- ") || trimmed == "-"
	}
	return false
}

// topLevelKey splits a document-level `key: value` line. A line that is
// indented, blank, commented, or not a mapping entry yields ok == false —
// indentation is what keeps a `kind:` nested inside some unrelated structure
// from speaking for the document.
func topLevelKey(line string) (key, value string, ok bool) {
	if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' || line[0] == '-' {
		return "", "", false
	}
	idx := strings.Index(line, ":")
	if idx <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+1:])
	if i := strings.Index(value, " #"); i >= 0 {
		value = strings.TrimSpace(value[:i])
	}
	if key == "" || strings.ContainsAny(key, " \t") {
		return "", "", false
	}
	return key, value, true
}

// unquote strips one layer of YAML quoting from a scalar.
func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

// cloudformationFamilyTag marks a rule as belonging to the CloudFormation
// family, which scopes itself with
//
//	{"*.template", "*.json", "*.yaml", "*.yml"}
//
// on 31 of its 31 single-format rules — the widest catch-all in the catalogue.
// A CloudFormation rule therefore applied to every YAML and every JSON file in
// any repository.
const cloudformationFamilyTag = "cloudformation"

// awsResourceType matches the `Type:` of a CloudFormation resource in either
// serialisation: `Type: AWS::S3::Bucket` in YAML, `"Type": "AWS::S3::Bucket"`
// in JSON. The `AWS::`, `Alexa::` and `Custom::` namespaces are CloudFormation's
// own and appear nowhere else, which is what makes this a document test rather
// than a keyword.
var awsResourceType = regexp.MustCompile(`["']?Type["']?\s*:\s*["']?(?:AWS|Alexa|Custom)::`)

// isCloudFormationTemplate reports whether content is a CloudFormation (or SAM)
// template.
//
// Unlike the other detectors here this one does not read top-level keys, because
// the family covers JSON as well as YAML and a JSON template indents everything.
// It asks instead for the two things a template cannot omit and nothing else
// writes: the format-version declaration, or a resource in an AWS type
// namespace. SAM templates are covered by the `Transform` line they must carry.
//
// It errs toward applying: any ONE of the three is enough.
func isCloudFormationTemplate(_ string, content []byte) bool {
	if bytes.Contains(content, []byte("AWSTemplateFormatVersion")) {
		return true
	}
	if awsResourceType.Match(content) {
		return true
	}
	if bytes.Contains(content, []byte("AWS::Serverless")) {
		// SAM: `Transform: AWS::Serverless-2016-10-31`.
		return true
	}
	// A top-level `Resources:` — capital R, which is CloudFormation's own
	// section name. The Serverless Framework spells its raw-CFN block
	// `resources:` and an ARM template spells its array `resources:`, both
	// lower-case, so the capital is load-bearing and this check is
	// case-sensitive on purpose.
	//
	// It is here because the first two tests were stricter than the format:
	// a reduced template, a macro fragment or an included snippet carries the
	// section without necessarily carrying a `Type:` line in the same file.
	for _, doc := range splitYAMLDocuments(string(content)) {
		for _, line := range strings.Split(doc, "\n") {
			if key, value, ok := topLevelKey(line); ok && key == "Resources" && value == "" {
				return true
			}
		}
	}
	return false
}

// githubActionsFamilyTag and ciPipelineFamilyTag mark the two CI families.
// Between them 38 of their 39 single-format rules were scoped by a YAML
// catch-all — ghaFilePatterns and ciFilePatterns both list the specific name
// AND `*.yml`/`*.yaml`, which is the shape that made the specific name
// decoration in the Serverless family.
const (
	githubActionsFamilyTag = "github-actions"
	ciPipelineFamilyTag    = "ci-cd"
)

// isGitHubActionsWorkflow reports whether content is a GitHub Actions workflow.
//
// A workflow declares `jobs:` at the top level and nothing else in common use
// does. The second test is what a job is made of: `runs-on`, `steps` or `uses`.
// Requiring both keeps a document that merely has a `jobs:` key — a Nomad spec,
// an arbitrary config — out of the family.
//
// `on:` is deliberately NOT required. YAML 1.1 reads a bare `on` as the boolean
// true, so workflows in the wild write it quoted, unquoted, or not at all when
// the workflow is only ever called; keying on it would make the gate depend on
// a quoting accident.
func isGitHubActionsWorkflow(_ string, content []byte) bool {
	var hasJobs bool
	for _, doc := range splitYAMLDocuments(string(content)) {
		for _, line := range strings.Split(doc, "\n") {
			if key, _, ok := topLevelKey(line); ok && key == "jobs" {
				hasJobs = true
			}
		}
	}
	if !hasJobs {
		return false
	}
	return bytes.Contains(content, []byte("runs-on")) ||
		bytes.Contains(content, []byte("steps:")) ||
		bytes.Contains(content, []byte("uses:"))
}

// isGitLabPipeline reports whether content is a GitLab CI pipeline.
//
// GitLab has no single mandatory key, so the test is the shape: a pipeline-level
// keyword at the top level, or a top-level job — a mapping entry whose own block
// declares `script:` or `trigger:`, which is what makes a GitLab job a job.
func isGitLabPipeline(content []byte) bool {
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		key, value, ok := topLevelKey(line)
		if !ok {
			continue
		}
		switch key {
		// GitLab's pipeline-level keywords. `variables`, `image`, `services`,
		// `before_script`, `after_script` and `cache` are here because a
		// pipeline may consist of nothing else — a fixture or an `include`d
		// fragment often does — and because Azure Pipelines spells its
		// variables block the same way, which is also a CI pipeline.
		case "stages", "stage", "workflow", "default", "include", "variables",
			"image", "services", "before_script", "after_script", "cache":
			return true
		}
		if value != "" {
			continue // A scalar cannot be a job.
		}
		if blockDeclares(lines[i+1:], "script", "trigger") {
			return true
		}
	}
	return false
}

// blockDeclares reports whether the indented block beginning at rest opens with
// one of the given keys at its own level.
func blockDeclares(rest []string, keys ...string) bool {
	for _, line := range rest {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if line == trimmed {
			return false // Back at the top level: the block ended.
		}
		for _, k := range keys {
			if strings.HasPrefix(trimmed, k+":") {
				return true
			}
		}
	}
	return false
}

// isCIPipeline accepts either CI dialect.
//
// The ci-cd rules are named for the concern rather than the vendor — "CI script
// pipes curl to shell", "CI uses Docker-in-Docker", "CI service uses latest tag"
// — and three of the eleven are GitLab-specific only in their wording. A
// GitHub Actions workflow is a CI pipeline, so the gate admits one.
func isCIPipeline(path string, content []byte) bool {
	return isGitHubActionsWorkflow(path, content) || isGitLabPipeline(content)
}

// ansibleFamilyTag marks the Ansible family, 42 of whose 43 single-format rules
// were scoped by `{"*.yml", "*.yaml"}` alone.
const ansibleFamilyTag = "ansible"

// ansibleKeyMarkers are keys only an Ansible document writes, matched as KEYS
// rather than as substrings.
//
// The line anchor is what the first version got wrong. Matching `tasks:`
// anywhere in the content admitted a CloudFormation template whose Description
// reads "This template accomplishes the following tasks: (1) applies a name
// tag…" — prose, in a field, in a document that is not remotely Ansible. Six
// files in the corpus outside the Ansible repository contain a bare `tasks:`
// substring. A key is the thing the marker means, so a key is what it matches.
//
// The optional `- ` is because a playbook's top level is a SEQUENCE: its keys
// are written `- hosts: all`.
//
// Case-SENSITIVE, and that is load-bearing too. YAML keys are case-sensitive
// and every Ansible key is lower-case, while the capitalised schemas are full
// of collisions: `Roles:` is a CloudFormation IAM property, and it admitted
// MANAGEDAD.cfn.yaml to the Ansible family under a case-insensitive match.
var ansibleKeyMarkers = regexp.MustCompile(`(?m)^[ \t]*-?[ \t]*(?:hosts|tasks|pre_tasks|post_tasks|roles|` +
	`handlers|become|become_user|become_method|gather_facts|vars_files|vars_prompt|` +
	`include_tasks|import_tasks|include_role|import_playbook|include_vars|` +
	`delegate_to|with_items|with_dict|galaxy_info|collections|serial|any_errors_fatal)[ \t]*:`)

// ansibleTokenMarkers are Ansible's own namespaces, which may appear anywhere:
// a collection-qualified module name, or an `ansible_` fact or connection
// variable. Each is anchored enough to be safe unanchored.
var ansibleTokenMarkers = regexp.MustCompile(`(?i)\b(?:ansible|community|amazon|kubernetes|containers|google)\.` +
	`[a-z0-9_]+\.[a-z0-9_]+|\bansible_[a-z0-9_]+`)

// isAnsibleDocument reports whether content is an Ansible playbook, task file,
// role file or requirements file.
//
// It errs toward applying, and further than the other detectors here do: ONE
// marker is enough. That is deliberate. Ansible has no format declaration, no
// `apiVersion`, no mandatory key — a role's defaults/main.yml is an ordinary
// mapping of arbitrary names — so a strict test would silently take the family
// off exactly the files it is meant to read. A generous test costs a false
// finding; a strict one costs a missed credential.
func isAnsibleDocument(_ string, content []byte) bool {
	return ansibleKeyMarkers.Match(content) || ansibleTokenMarkers.Match(content) ||
		ansibleTaskFile.Match(content)
}

// ansibleTaskFile matches a TOP-LEVEL sequence of named items — `- name: …` at
// column zero.
//
// A role's tasks/main.yml is exactly that and carries none of the keys above:
// no `hosts:`, no `tasks:`, just tasks. Without this a task file was not
// recognised as Ansible at all, which the per-task no_log rule found
// immediately.
//
// Column zero is what makes it safe. A GitHub Actions workflow's `steps:` are a
// sequence of `- name:` items too, but they are nested under a job, and no
// other format this meets puts a named sequence at the document's top level.
var ansibleTaskFile = regexp.MustCompile(`(?m)^-[ \t]+name[ \t]*:`)

// documentFormatTags is the vocabulary of tags that name a DOCUMENT FORMAT,
// as opposed to the severity, theme or cloud provider a rule is also tagged
// with. A rule carrying more than one of these describes a condition that
// several formats express, and no single format's document kind can speak for
// it.
//
// This is not hypothetical. IAC-007 ("Container runs in privileged mode",
// CRITICAL) absorbed IAC-065 (CloudFormation) and IAC-237 (Kustomize) and
// carries all three tags so their waivers keep resolving. Gating on the
// `kustomize` tag alone therefore switched it off wherever the document was
// not a kustomization — measured as 9 findings lost on Kubernetes manifests in
// kubernetes/examples, on a rule that has nothing to do with Kustomize beyond
// having inherited its retired ID.
var documentFormatTags = map[string]bool{
	"kubernetes": true, "kustomize": true, "serverless": true,
	"cloudformation": true, "terraform": true, "ansible": true,
	"github-actions": true, "arm": true, "docker": true,
	"docker-compose": true, "helm": true, "ci-cd": true,
}

// detectorCanDecide reports whether the detectors in this file can read the
// document at path at all. See the note in dropRulesOutsideTheirDocumentKind.
func detectorCanDecide(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yml", ".yaml", ".json", ".template", ".ts", ".js":
		return true
	}
	return false
}

// gatesFor returns the document-kind gates that can speak for a rule, and
// whether every document format the rule names has one.
//
// A rule that names several formats describes a condition several formats
// express, and the question is whether ANY of them fits the document in hand.
// Two cases fall out of that, and both matter:
//
//   - IAC-007 ("Container runs in privileged mode", CRITICAL) names kubernetes,
//     cloudformation and kustomize, because it absorbed IAC-065 and IAC-237 and
//     carries their tags so their waivers keep resolving. Kubernetes has no
//     gate — a Kubernetes rule legitimately applies to any document declaring
//     Kubernetes resources, including an Ansible task that embeds one — so no
//     gate can speak for IAC-007 and it is left alone. Keying on the kustomize
//     tag alone once switched it off across 9 manifests.
//   - IAC-011, IAC-155 and IAC-159 name github-actions AND ci-cd. Both have
//     gates, and a document that is a GitHub Actions workflow satisfies either,
//     so the rule is dropped only where the document is neither dialect.
//
// This is the general form of the "exactly one format" rule it replaces, and it
// behaves identically for a rule naming one.
func gatesFor(r *rules.Rule) ([]documentKindGate, bool) {
	var named, found int
	var out []documentKindGate
	for _, t := range r.Tags {
		if !documentFormatTags[t] {
			continue
		}
		named++
		for _, g := range documentKindGates {
			if g.tag == t {
				out = append(out, g)
				found++
			}
		}
	}
	return out, named > 0 && named == found
}

// documentKindGate binds a rule family to the question of whether the document
// in hand is of that family's kind.
//
// The table is the point. Two families carried the same defect, and a third
// added tomorrow inherits the gate by declaring a row here rather than by
// anyone remembering to edit a filter.
type documentKindGate struct {
	tag string
	is  func(path string, content []byte) bool
	// why states, in the finding's own record, what the document would have
	// had to say for the rule to apply.
	why string
}

var documentKindGates = []documentKindGate{
	{
		tag: serverlessFamilyTag,
		is:  isServerlessManifest,
		why: "this rule describes a Serverless Framework manifest, and this " +
			"document declares neither `service` nor `provider`, so it is not one. " +
			"The file name is a hint about what to parse, not evidence that the " +
			"rule applies",
	},
	{
		tag: cloudformationFamilyTag,
		is:  isCloudFormationTemplate,
		why: "this rule describes a CloudFormation template, and this document " +
			"declares no AWSTemplateFormatVersion, no resource in an AWS:: type " +
			"namespace and no Serverless transform, so it is not one. The file name " +
			"is a hint about what to parse, not evidence that the rule applies",
	},
	{
		tag: githubActionsFamilyTag,
		is:  isGitHubActionsWorkflow,
		why: "this rule describes a GitHub Actions workflow, and this document " +
			"declares no top-level `jobs:` with steps in it, so it is not one. The " +
			"file name is a hint about what to parse, not evidence that the rule applies",
	},
	{
		tag: ciPipelineFamilyTag,
		is:  isCIPipeline,
		why: "this rule describes a CI pipeline, and this document is neither a " +
			"GitHub Actions workflow nor a GitLab pipeline: it declares no top-level " +
			"`jobs:` with steps, no pipeline-level keyword and no job with a `script:`. " +
			"The file name is a hint about what to parse, not evidence that the rule applies",
	},
	{
		tag: ansibleFamilyTag,
		is:  isAnsibleDocument,
		why: "this rule describes an Ansible playbook, task file or role, and this " +
			"document carries no Ansible marker at all — no `hosts:`, no `tasks:`, no " +
			"`become:`, no collection-qualified module name. The file name is a hint " +
			"about what to parse, not evidence that the rule applies",
	},
	{
		tag: kustomizeFamilyTag,
		is:  isKustomization,
		why: "this rule describes a Kustomize kustomization, and this document " +
			"declares no `kind: Kustomization`, no kustomize.config.k8s.io " +
			"apiVersion and no kustomization-only field, so it is not one. " +
			"The file name is a hint about what to parse, not evidence that the " +
			"rule applies",
	},
}

// dropRulesOutsideTheirDocumentKind removes findings from a rule family whose
// document is not of that family's kind.
//
// Like every other refiner here it is handed a recorder rather than dropping
// silently: a filter that removes findings and the reason for removing them in
// the same statement produces a result indistinguishable from having had
// nothing to remove.
func dropRulesOutsideTheirDocumentKind(path string, in []findings.Finding, content []byte, set *rules.RuleSet, drop refuteFunc) []findings.Finding {
	if len(in) == 0 || set == nil {
		return in
	}
	// "I cannot read this" is not "this is not one". Every detector here reads
	// YAML, JSON or a JS/TS config; handed a .toml or .cfg it would answer no
	// for the wrong reason and silently take the family off a format it never
	// examined. IAC-050 is the case that found this: it is a CI rule and its
	// file patterns include *.toml and *.cfg.
	if !detectorCanDecide(path) {
		return in
	}
	// Each detector is run at most once per file, and only when a rule of its
	// family actually matched.
	type memo struct{ checked, is bool }
	seen := make(map[string]memo, len(documentKindGates))

	kept := in[:0]
	for _, f := range in {
		rule, ok := set.ByID(f.RuleID)
		if !ok {
			kept = append(kept, f)
			continue
		}
		gates, allGated := gatesFor(rule)
		if !allGated {
			kept = append(kept, f)
			continue
		}
		var fits bool
		var why []string
		for _, gate := range gates {
			m, done := seen[gate.tag]
			if !done {
				m = memo{checked: true, is: gate.is(path, content)}
				seen[gate.tag] = m
			}
			if m.is {
				fits = true
				break
			}
			why = append(why, gate.why)
		}
		if fits {
			kept = append(kept, f)
			continue
		}
		drop(f, strings.Join(why, "; and "))
	}
	return kept
}
