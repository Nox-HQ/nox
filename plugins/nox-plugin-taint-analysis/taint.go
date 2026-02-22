package main

// TaintSource records where a variable became tainted.
type TaintSource struct {
	VarName string
	Line    int
	Kind    string // "http_query", "http_body", "http_header", "cli_arg", "env_var", "stdin"
	Expr    string // raw expression text
}

// TaintFlow records a complete source-to-sink data flow.
type TaintFlow struct {
	Source   TaintSource
	SinkLine int
	SinkExpr string
	RuleID   string
	CWE      string
	FilePath string
	FuncName string
	Language string
}

// TaintState tracks which variables are currently tainted within a function scope.
type TaintState struct {
	vars map[string]TaintSource
}

// NewTaintState creates an empty taint state.
func NewTaintState() *TaintState {
	return &TaintState{vars: make(map[string]TaintSource)}
}

// Mark records a variable as tainted by the given source.
func (ts *TaintState) Mark(varName string, src TaintSource) {
	ts.vars[varName] = src
}

// IsTainted reports whether a variable is currently tainted.
func (ts *TaintState) IsTainted(varName string) bool {
	_, ok := ts.vars[varName]
	return ok
}

// Get returns the taint source for a variable, if tainted.
func (ts *TaintState) Get(varName string) (TaintSource, bool) {
	src, ok := ts.vars[varName]
	return src, ok
}

// Clear removes taint from a variable (e.g., after sanitization).
func (ts *TaintState) Clear(varName string) {
	delete(ts.vars, varName)
}

// Reset clears all taint state (e.g., at function boundaries).
func (ts *TaintState) Reset() {
	ts.vars = make(map[string]TaintSource)
}

// TaintedVars returns all currently tainted variable names.
func (ts *TaintState) TaintedVars() []string {
	names := make([]string, 0, len(ts.vars))
	for name := range ts.vars {
		names = append(names, name)
	}
	return names
}
