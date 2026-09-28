//go:build !race

package rules_test

// raceEnabled: this binary was built with -race (see prefixplan_equiv_test.go).
const raceEnabled = false
