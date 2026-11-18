package engine

// scopeStack decides which unit a statement belongs to once a function body
// has ended.
//
// The Python, Ruby, Lua, PHP, Perl and PowerShell extractors opened a unit at
// each function header and never left it, so every statement after the first
// function — top-level code, an `if __name__ == "__main__":` block, a script's
// trailing call — was recorded as part of the last function declared above it.
// That merged two scopes the language keeps apart: a flow could join a
// function's local to a module-level sink, and anything reading the units as
// "what this function does" (the call graph) saw calls the function never
// makes.
//
// A frame closes in one of two ways, matching how the language ends a body:
//   - by indentation (Python, and Ruby and Lua, whose `end` sits at the
//     header's indentation in conventionally formatted code): the first
//     non-blank line indented no deeper than the header ends it;
//   - by braces (PHP, Perl, PowerShell): once the body's opening brace has been
//     seen, the line that brings the depth back to the header's level ends it.
//     A header whose brace is on the next line (Allman style) is not closed by
//     the header line itself, because the body has not been entered yet.
type scopeStack struct {
	module *unitDraft
	frames []scopeFrame
	// depth is the running brace depth, for brace-closed languages.
	depth int
}

type scopeFrame struct {
	unit *unitDraft
	// level is the header's indentation (indent mode) or the brace depth
	// before the header (brace mode).
	level   int
	entered bool
}

func newScopeStack(module *unitDraft) *scopeStack { return &scopeStack{module: module} }

// current is the unit the next statement belongs to.
func (s *scopeStack) current() *unitDraft {
	if n := len(s.frames); n > 0 {
		return s.frames[n-1].unit
	}
	return s.module
}

// dedent closes every frame whose header is indented at least as deep as a
// non-blank line at indent, and returns the unit that line belongs to. Called
// for every non-blank line before the line is interpreted, including a
// function header, so a header at the same level as the previous one closes
// its sibling.
func (s *scopeStack) dedent(indent int) *unitDraft {
	for len(s.frames) > 0 && s.frames[len(s.frames)-1].level >= indent {
		s.frames = s.frames[:len(s.frames)-1]
	}
	return s.current()
}

// pushIndent opens a unit whose header sits at indent.
func (s *scopeStack) pushIndent(u *unitDraft, indent int) {
	s.frames = append(s.frames, scopeFrame{unit: u, level: indent})
}

// pushBrace opens a unit whose header line starts at the current brace depth.
// Call it before advance for the header line, so a brace on the header itself
// enters the body.
func (s *scopeStack) pushBrace(u *unitDraft) {
	s.frames = append(s.frames, scopeFrame{unit: u, level: s.depth})
}

// advance applies one line's brace delta and closes every frame the line
// ends. It returns the unit the NEXT line belongs to; the line itself stays
// with the unit that was current when it started, so a closing `}` line —
// structural anyway — never moves a statement.
func (s *scopeStack) advance(code string) *unitDraft {
	// The peak matters as well as the end: `sub f { run(); }` enters and leaves
	// its body on one line.
	peak := s.depth
	for i := 0; i < len(code); i++ {
		switch code[i] {
		case '{':
			s.depth++
			peak = max(peak, s.depth)
		case '}':
			s.depth--
		}
	}
	if n := len(s.frames); n > 0 && peak > s.frames[n-1].level {
		s.frames[n-1].entered = true
	}
	for len(s.frames) > 0 {
		top := &s.frames[len(s.frames)-1]
		if s.depth > top.level {
			break
		}
		if !top.entered {
			break
		}
		s.frames = s.frames[:len(s.frames)-1]
	}
	return s.current()
}
