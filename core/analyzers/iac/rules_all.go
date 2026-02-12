package iac

import "github.com/nox-hq/nox/core/rules"

// builtinIaCRules aggregates all built-in IaC security rules from all rule files.
func builtinIaCRules() []rules.Rule {
	all := builtinBaseIaCRules()
	all = append(all, builtinAnsibleRules()...)
	all = append(all, builtinKustomizeRules()...)
	all = append(all, builtinServerlessRules()...)
	all = append(all, builtinExpandedIaCRules()...)
	return all
}
