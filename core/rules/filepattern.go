package rules

import (
	"path/filepath"
	"strings"
)

// filePatternKind is how a compiled file pattern is decided.
type filePatternKind uint8

const (
	// globPattern falls back to filepath.Match.
	globPattern filePatternKind = iota
	// literalPattern has no glob syntax: it matches by equality.
	literalPattern
	// suffixPattern is `*` followed by literal text with no separator: it
	// matches a base name ending in that text.
	suffixPattern
)

// filePattern is a FilePatterns or IgnoreFilePatterns entry compiled once, so
// the rule loop does not run the glob machinery for `*.py` or `Dockerfile` on
// every file for every rule (#736: 7.6% of scan CPU on crewAI). It decides
// exactly as filepath.Match on the path or its base name did.
type filePattern struct {
	kind filePatternKind
	// pattern is the entry as written; text is what the kind compares
	// against (the suffix, for suffixPattern).
	pattern, text string
}

func compileFilePattern(p string) filePattern {
	if !strings.ContainsAny(p, `*?[\`) {
		return filePattern{kind: literalPattern, pattern: p, text: p}
	}
	if rest, ok := strings.CutPrefix(p, "*"); ok && !strings.ContainsAny(rest, `*?[\/`) {
		return filePattern{kind: suffixPattern, pattern: p, text: rest}
	}
	return filePattern{kind: globPattern, pattern: p, text: p}
}

func compileFilePatterns(ps []string) []filePattern {
	if len(ps) == 0 {
		return nil
	}
	out := make([]filePattern, len(ps))
	for i, p := range ps {
		out[i] = compileFilePattern(p)
	}
	return out
}

// matches reports whether the pattern accepts path or its base name.
func (f filePattern) matches(path, base string) bool {
	switch f.kind {
	case literalPattern:
		return path == f.text || base == f.text
	case suffixPattern:
		// A `*` never crosses a separator, so the full path matches only when
		// it is its own base name; the base name alone decides.
		return strings.HasSuffix(base, f.text) && !strings.ContainsRune(base, filepath.Separator)
	}
	if m, _ := filepath.Match(f.text, path); m {
		return true
	}
	m, _ := filepath.Match(f.text, base)
	return m
}

// compiledFor returns the compiled form of ps: the cache when it still holds
// exactly these patterns, otherwise a fresh compilation. A Rule built directly,
// or one whose patterns were changed after RuleSet.Add, decides the same way.
func compiledFor(cache []filePattern, ps []string) []filePattern {
	if len(cache) == len(ps) {
		fresh := true
		for i := range ps {
			if cache[i].pattern != ps[i] {
				fresh = false
				break
			}
		}
		if fresh {
			return cache
		}
	}
	return compileFilePatterns(ps)
}
