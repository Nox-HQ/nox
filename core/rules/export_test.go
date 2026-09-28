package rules

// PrefixFindAll exposes the literal-prefix path to the equivalence test:
// the locations it returns for pattern, and whether the pattern has a plan.
func PrefixFindAll(pattern string, content []byte, submatch bool) ([][]int, bool) {
	p := planFor(pattern)
	if p == nil || !p.usable(content) {
		return nil, false
	}
	return p.findAll(content, submatch), true
}
