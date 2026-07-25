package engine

import "strings"

// argInfo analyzes a call's raw argument text into the argument-shape evidence
// the engine needs for the catalog's per-sink notes: positional argument count,
// whether shell=True/shell:true is present, which variables appear as arguments,
// and whether a variable appears in the FIRST positional argument (the SQL
// string of cursor.execute, the command of subprocess.run). Best-effort and
// deterministic.
func argInfo(lang langKind, c callChain) sinkArgDraft {
	// Positional arity and shell=True are counted from the RAW args (literals
	// intact) so a string-literal argument is not lost. Variable reads come from
	// the CODE args (literals blanked) so identifiers inside strings never leak.
	rawParts := splitTopLevelArgs(c.rawArgs)
	codeParts := splitTopLevelArgs(c.codeArgs)
	info := sinkArgDraft{argCount: countPositional(rawParts, codeParts)}

	for _, p := range rawParts {
		if isShellTrue(lang, p) {
			info.shellTrue = true
		}
	}

	seen := map[string]struct{}{}
	for idx, p := range codeParts {
		if strings.TrimSpace(p) == "" {
			continue
		}
		trimmed := strings.TrimSpace(p)
		// A first argument that is a list/array literal ([...]) is an arg VECTOR,
		// not a command string — its inner variables do not make the first
		// positional argument "a tainted command", which is what firstArgTainted
		// must capture (subprocess.run(["ls", cmd]) is safe; subprocess.run(cmd)
		// is not).
		firstIsVector := idx == 0 && strings.HasPrefix(trimmed, "[")
		slotVars := freeIdentifiers(lang, p)
		// Record the positional slot's variables so the interprocedural pass can
		// map argument position → callee parameter. Keyword args occupy no fixed
		// position and are excluded, so positionalVars[i] is the i-th POSITIONAL
		// argument's variables.
		if !isKeywordArg(p) {
			info.positionalVars = append(info.positionalVars, append([]string(nil), slotVars...))
			// Record the slot's code text (literals already blanked) so the engine
			// can detect a source used directly as this argument — sink(source()).
			info.positionalArgs = append(info.positionalArgs, p)
		}
		for _, id := range slotVars {
			if _, dup := seen[id]; !dup {
				seen[id] = struct{}{}
				info.taintedArgVars = append(info.taintedArgVars, id)
			}
			if idx == 0 && !isKeywordArg(p) && !firstIsVector {
				info.firstArgTainted = true
			}
		}
	}
	sortStrings(info.taintedArgVars)
	// Role-awareness for LLM prompt sinks: if this call is chat-message-shaped
	// (a messages=[{role,content}] list or a system= parameter), map each argument
	// variable to the chat role it lands in and note whether a static system message
	// establishes the instruction/data boundary. Populated for Python only; other
	// languages keep the role-blind behavior (documented in detectPromptRoles).
	info.promptRoles, info.promptStaticSystem = detectPromptRoles(lang, c.rawArgs, c.codeArgs)
	return info
}

// splitTopLevelArgs splits raw argument text on commas that are not nested
// inside brackets, returning each argument's text. Empty input yields no args.
func splitTopLevelArgs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, raw[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, raw[start:])
	return parts
}

// countPositional returns the number of positional (non-keyword) arguments.
// It counts a slot as present when its RAW text is non-empty (so a string
// literal, blanked in the code view, still counts) and classifies keyword-ness
// from the CODE view (blanked), so an `=` inside a string literal — e.g. a SQL
// `WHERE x = %s` — is never mistaken for a keyword argument. rawParts and
// codeParts are the same top-level split of the same call, so they align by
// index; a missing code counterpart falls back to the raw text.
func countPositional(rawParts, codeParts []string) int {
	n := 0
	for i, raw := range rawParts {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		code := raw
		if i < len(codeParts) {
			code = codeParts[i]
		}
		if isKeywordArg(code) {
			continue
		}
		n++
	}
	return n
}

// isKeywordArg reports whether an argument is a keyword/named argument
// (`shell=True`, `timeout=5`) rather than positional. A top-level `=` not part
// of a comparison marks it. Bracket-nested `=` is ignored.
func isKeywordArg(p string) bool {
	depth := 0
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '=':
			if depth != 0 {
				continue
			}
			if i+1 < len(p) && p[i+1] == '=' {
				return false
			}
			if i > 0 {
				switch p[i-1] {
				case '=', '!', '<', '>', '+', '-', '*', '/':
					return false
				}
			}
			return true
		}
	}
	return false
}

// isShellTrue reports whether an argument expresses shell=True (Python) or
// shell:true (JS object property). Whitespace-insensitive.
func isShellTrue(lang langKind, p string) bool {
	compact := strings.ReplaceAll(strings.ReplaceAll(p, " ", ""), "\t", "")
	if lang == langJavaScript {
		return strings.Contains(compact, "shell:true")
	}
	return strings.Contains(compact, "shell=True")
}
