package engine

import "strings"

// Rust's std::process::Command is a builder: the program is named once, in
// Command::new, and the argument vector is assembled by .arg/.args calls that
// reach execve with no shell. Which sink a tainted value reaches therefore
// depends on state the .arg call itself does not carry:
//
//   - the PROGRAM. Command::new("sh").arg("-c").arg(x) hands x to a shell, a
//     command injection (CWE-78). Command::new("git").arg(x) hands it to git
//     as one argument, which can at worst be read as an option: argument
//     injection (CWE-88). This is the argv exemption the other languages
//     apply (see shellPrograms), including its limit: a shell as the program
//     voids it.
//   - a literal "--" earlier in the same builder, after which git, cargo and
//     most CLIs read every remaining argument as a positional, so an
//     option-looking value is harmless.
//
// The recognizer sees one logical line at a time, so the builder is followed
// here: through a method chain, and through a `let mut cmd = Command::new(..)`
// binding that later statements call .arg on.
//
// The classification is a rename of the call's last segment, which is what the
// catalog's suffix lookup keys on: `shell_arg`/`shell_args` reach the CWE-78
// sink, plain `arg`/`args` the CWE-88 one, and `literal_arg`/`separated_arg`/
// `literal_new` reach none. The earlier segments are kept, so two calls in one
// chain still have distinct keys.

const (
	rustShellArg      = "shell_arg"
	rustShellArgs     = "shell_args"
	rustLiteralArg    = "literal_arg"
	rustSeparatedArg  = "separated_arg"
	rustLiteralNew    = "literal_new"
	rustSeparatorText = `"--"`
)

// rustBuilderMethods return the builder, so a chain through them is still the
// Command being assembled.
var rustBuilderMethods = map[string]bool{
	"arg": true, "args": true, "env": true, "envs": true, "env_clear": true,
	"env_remove": true, "current_dir": true, "stdin": true, "stdout": true,
	"stderr": true, "uid": true, "gid": true, "process_group": true,
}

// rustCmdState is what is known of a Command builder at a point in a chain.
type rustCmdState struct {
	shell bool   // the program is a shell (or env)
	sep   bool   // a literal "--" has been passed
	root  string // the tracked variable the builder was reached through, if any
}

// rustCommands follows Command builders across the statements of one function.
type rustCommands struct {
	vars map[string]rustCmdState
	// A builder is usually written one call per line, each line starting with
	// the `.` and recognized as a statement of its own. carry is the builder
	// state the previous line ended with, and continuation says the line being
	// recognized starts with `.` and so continues it.
	carry        *rustCmdState
	continuation bool
}

// beginLine tells the classifier whether the next statement continues the
// previous line's builder.
func (rc *rustCommands) beginLine(code string) {
	rc.continuation = strings.HasPrefix(strings.TrimSpace(code), ".")
}

func newRustCommands() *rustCommands {
	return &rustCommands{vars: map[string]rustCmdState{}}
}

// rewrite classifies the Command calls of one statement. lhs is the variable
// the statement assigns, if any.
func (rc *rustCommands) rewrite(lhs string, calls []callChain) []callChain {
	// state after each call, keyed by its ORIGINAL callee: a chain continues
	// from its parent's callee, whatever that call was renamed to.
	after := map[string]rustCmdState{}
	out := append([]callChain(nil), calls...)
	best, bestDots := "", -1
	for i, c := range calls {
		last := rustLastSegment(c.callee)
		switch {
		case c.callee == "Command.new" || strings.HasSuffix(c.callee, ".Command.new"):
			st := rustCmdState{shell: namesShellProgram(rustFirstPositional(c.rawArgs))}
			after[c.callee] = st
			if len(argInfo(langRust, c).taintedArgVars) == 0 {
				// A literal executable: nothing in the call can be tainted, but
				// with no variable named the engine would charge the call with
				// every variable the statement reads.
				out[i].callee = rustRename(c.callee, rustLiteralNew)
			}
			if n := dots(c.callee); n > bestDots {
				best, bestDots = c.callee, n
			}
		case rustBuilderMethods[last]:
			parent := rustParent(c.callee)
			st, ok := after[parent]
			if !ok && parent == "" && rc.continuation && rc.carry != nil {
				st, ok = *rc.carry, true // `.arg(x)` on a line of its own
			}
			if !ok {
				v, tracked := rc.vars[parent]
				if !tracked {
					continue // a receiver nothing here says is a Command
				}
				st = v
				st.root = parent
			}
			if last == "arg" || last == "args" {
				out[i].callee, st = rustClassifyArg(c, last, st)
			}
			after[c.callee] = st
			if n := dots(c.callee); n > bestDots {
				best, bestDots = c.callee, n
			}
		}
	}
	rc.carry = nil
	if best == "" {
		return out
	}
	final := after[best]
	// A tracked variable keeps what its last .arg left behind, so a later
	// statement's `cmd.arg(x)` sees the program and any separator.
	if final.root != "" {
		rc.vars[final.root] = final
	}
	// A binding whose value is the builder (not what running it returns).
	if lhs != "" && rc.endsAsBuilder(best, calls, after) {
		final.root = lhs
		rc.vars[lhs] = final
	}
	rc.carry = &final
	return out
}

// endsAsBuilder reports whether the chain ending at best stops there: a call
// continuing it that is not a builder method (.output(), .spawn(), .status())
// makes the assigned value something else.
func (rc *rustCommands) endsAsBuilder(best string, calls []callChain, after map[string]rustCmdState) bool {
	for _, c := range calls {
		if strings.HasPrefix(c.callee, best+".") {
			if _, isBuilder := after[c.callee]; !isBuilder {
				return false
			}
		}
	}
	return true
}

// rustClassifyArg decides which sink an .arg/.args call reaches and returns
// the new callee with the builder state after the call.
func rustClassifyArg(c callChain, method string, st rustCmdState) (string, rustCmdState) {
	if len(argInfo(langRust, c).taintedArgVars) == 0 {
		// Only literals: no value of ours can reach it. (The separator is
		// still recorded below.)
		st = rustNoteSeparator(c, method, st)
		return rustRename(c.callee, rustLiteralArg), st
	}
	protected := st.sep || rustVariablesFollowSeparator(c, method)
	st = rustNoteSeparator(c, method, st)
	switch {
	case st.shell:
		if method == "args" {
			return rustRename(c.callee, rustShellArgs), st
		}
		return rustRename(c.callee, rustShellArg), st
	case protected:
		return rustRename(c.callee, rustSeparatedArg), st
	}
	return c.callee, st
}

// rustNoteSeparator records a literal "--" passed by this call.
func rustNoteSeparator(c callChain, method string, st rustCmdState) rustCmdState {
	for _, e := range rustArgElements(c.rawArgs, method) {
		if e == rustSeparatorText {
			st.sep = true
		}
	}
	return st
}

// rustVariablesFollowSeparator reports whether an .args([...]) vector carries
// its own "--" with only literals before it, so every variable in the vector
// comes after the separator.
func rustVariablesFollowSeparator(c callChain, method string) bool {
	if method != "args" {
		return false
	}
	for _, e := range rustArgElements(c.rawArgs, method) {
		if e == rustSeparatorText {
			return true
		}
		if !strings.HasPrefix(e, `"`) {
			return false // a value before the separator
		}
	}
	return false
}

// rustArgElements returns the trimmed top-level elements of the call's
// argument: the one argument of .arg, or the items of an .args array literal.
// An .args argument that is not an array literal (an iterator, a variable) has
// no elements to read.
func rustArgElements(raw, method string) []string {
	raw = strings.TrimSpace(raw)
	if method == "arg" {
		return []string{raw}
	}
	open := strings.IndexByte(raw, '[')
	closeIdx := strings.LastIndexByte(raw, ']')
	if open < 0 || closeIdx <= open {
		return nil
	}
	parts := splitTopLevelArgs(raw[open+1 : closeIdx])
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// rustFirstPositional returns the first top-level argument's raw text.
func rustFirstPositional(raw string) string {
	parts := splitTopLevelArgs(raw)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func rustLastSegment(callee string) string {
	if i := strings.LastIndexByte(callee, '.'); i >= 0 {
		return callee[i+1:]
	}
	return callee
}

func rustParent(callee string) string {
	if i := strings.LastIndexByte(callee, '.'); i >= 0 {
		return callee[:i]
	}
	return ""
}

// rustRename replaces a callee's last segment.
func rustRename(callee, segment string) string {
	return rustParent(callee) + "." + segment
}
