package iac

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// gha workflow path prefix used to detect findings that belong to GitHub
// Actions workflows. Only findings under this path get context-aware
// downgrades.
const ghaWorkflowsPrefix = ".github/workflows/"

// servicesBlockRe matches a top-level `services:` block declared inside a
// job. Credentials declared under such a block (e.g. an ephemeral postgres
// container used only for the duration of a workflow run) are not deployable
// secrets and should not be flagged at the same severity as production
// configuration.
var servicesBlockRe = regexp.MustCompile(`(?m)^\s{2,}services:\s*$`)

// ephemeralTestDBRules is the set of rule IDs that, when fired on a GHA
// workflow file containing a `services:` block, are downgraded to info
// severity. These rules typically detect database credentials inline in
// configuration; in the GHA `services:` context they describe an ephemeral
// test container, not a deployable secret.
var ephemeralTestDBRules = map[string]bool{
	"IAC-254": true,
	"IAC-351": true,
	// SEC-073 is the credential-aware DB connection-string rule. The bare
	// scheme rule SEC-430 (postgres://) it superseded was retired in the
	// secrets rebuild, so only SEC-073 remains here.
	"SEC-073": true,
}

// permissionConsumers maps a workflow permission rule ID to a set of action
// invocation patterns that legitimately require that permission. When a
// finding is paired with a known consumer in the same file the severity is
// downgraded; bare permissions without a justifying action stay at original
// severity.
var permissionConsumers = map[string][]string{
	// contents: write — typical legitimate consumers create commits / PRs
	// / releases / publish docs.
	"IAC-314": {
		"peter-evans/create-pull-request",
		"goreleaser/goreleaser-action",
		"softprops/action-gh-release",
		"ncipollo/release-action",
		"actions/create-release",
		"stefanzweifel/git-auto-commit-action",
		"JamesIves/github-pages-deploy-action",
	},
	// packages: write — registry pushes for container images / language
	// package managers.
	"IAC-315": {
		"docker/login-action",
		"docker/build-push-action",
		"goreleaser/goreleaser-action",
	},
}

// ApplyGHAContext post-processes findings produced on GitHub Actions
// workflow files to downgrade well-known false positives. Exported so the
// scan pipeline can apply it to findings produced by analyzers other than
// IaC (e.g. secrets rules that fire on workflow YAML).
//
// The mutation is in-place via the returned slice and additional metadata
// is attached so operators can audit the decision.
func ApplyGHAContext(findingsList []findings.Finding, fileContent map[string][]byte) []findings.Finding {
	return applyGHAContext(findingsList, fileContent)
}

// ansibleRuleIDs is the set of rule IDs belonging to the Ansible family,
// derived from the rule table itself so a rule added there is covered here
// without a second list to keep in sync.
var ansibleRuleIDs = func() map[string]bool {
	ids := make(map[string]bool)
	for _, r := range builtinAnsibleRules() {
		ids[r.ID] = true
	}
	return ids
}()

// isGitHubActionsFile reports whether a path is a GitHub Actions workflow or a
// composite action definition.
//
// Composite actions are included deliberately. The workflows-only prefix left
// `action.yml` uncovered, and a composite step is REQUIRED to declare `shell:`
// — which is precisely the construct that was being misread as Ansible. Four
// of the five IAC-193 waivers in nox's own tree were on action.yml files.
func isGitHubActionsFile(path string) bool {
	p := filepath.ToSlash(path)
	if strings.HasPrefix(p, ghaWorkflowsPrefix) || strings.Contains(p, "/"+ghaWorkflowsPrefix) {
		return true
	}
	switch filepath.Base(p) {
	case "action.yml", "action.yaml":
		return true
	}
	return false
}

// applyGHAContext is the unexported implementation called by ApplyGHAContext
// and by the IaC analyzer's own post-pass.
func applyGHAContext(findingsList []findings.Finding, fileContent map[string][]byte) []findings.Finding {
	// An Ansible rule cannot mean what it says on a GitHub Actions file: a
	// workflow is not a playbook. Every Ansible rule is scoped to `*.yml` /
	// `*.yaml`, i.e. every YAML file in the repository, so `shell: bash` in a
	// composite action — which the step is required to declare — matched
	// IAC-193 "Ansible task uses shell module". These are dropped rather than
	// downgraded, because the finding is categorically wrong rather than less
	// severe; a downgrade would leave an operator triaging a rule that could
	// never apply. nox's own tree carried five waivers papering over this.
	//
	// Detection is by path, not content: an Ansible playbook is an ordinary
	// .yml file that never lives at .github/workflows/ or action.yml, so real
	// playbooks are untouched.
	kept := findingsList[:0]
	for _, f := range findingsList {
		if ansibleRuleIDs[f.RuleID] && isGitHubActionsFile(f.Location.FilePath) {
			continue
		}
		kept = append(kept, f)
	}
	findingsList = kept

	for i := range findingsList {
		f := &findingsList[i]
		path := f.Location.FilePath
		if !strings.HasPrefix(path, ghaWorkflowsPrefix) {
			continue
		}
		content := fileContent[path]
		if len(content) == 0 {
			continue
		}

		if ephemeralTestDBRules[f.RuleID] && servicesBlockRe.Match(content) {
			f.Severity = findings.SeverityInfo
			ensureMeta(f)
			f.Metadata["gha_context"] = "ephemeral_test_db"
			f.Metadata["original_severity"] = string(findings.SeverityCritical)
			continue
		}

		if consumers, ok := permissionConsumers[f.RuleID]; ok {
			if matchesAnyConsumer(content, consumers) {
				f.Severity = findings.SeverityLow
				ensureMeta(f)
				f.Metadata["gha_context"] = "justified_by_consumer_action"
				f.Metadata["original_severity"] = string(findings.SeverityMedium)
			}
		}
	}
	return findingsList
}

func ensureMeta(f *findings.Finding) {
	if f.Metadata == nil {
		f.Metadata = make(map[string]string)
	}
}

func matchesAnyConsumer(content []byte, consumers []string) bool {
	for _, c := range consumers {
		if strings.Contains(string(content), c) {
			return true
		}
	}
	return false
}
