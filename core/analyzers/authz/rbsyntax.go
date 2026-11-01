package authz

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// The Ruby reader shared by the Rails routes and controllers: a file is split
// into logical statements (a statement continues over brackets, trailing
// commas and leading-dot chains), and each statement carries how many blocks
// it opens and closes, so a caller can keep a stack without a Ruby parser.
//
// Structure is read from the lexically masked copy (comments, string bodies,
// heredocs and %w/%i literals are blank, so a word in one can neither open a
// block nor look like a route); values are read from the comment-free copy,
// where those literals are intact.

// rbFile is one Ruby source file.
type rbFile struct {
	path       string
	code       string // lexctx.MaskNonCode
	sans       string // comments blanked, strings kept
	lineStarts []int
}

func newRBFile(path string, raw []byte) *rbFile {
	return &rbFile{
		path:       path,
		code:       string(lexctx.MaskNonCode(lexctx.LangRuby, raw)),
		sans:       withoutComments(lexctx.LangRuby, raw),
		lineStarts: computeLineStarts(raw),
	}
}

// rbStmt is one logical statement: the byte range [start, end) of the file.
type rbStmt struct {
	start, end  int
	opens, ends int
}

func (s rbStmt) text(f *rbFile) string { return f.code[s.start:s.end] }
func (s rbStmt) sans(f *rbFile) string { return f.sans[s.start:s.end] }

var (
	rbModifierPrefixRe = regexp.MustCompile(`^(?:private|protected|public|private_class_method|module_function|memoize)\s+`)
	rbOpenRe           = regexp.MustCompile(`^(def|class|module|if|unless|while|until|case|begin|for)\b`)
	rbAssignOpenRe     = regexp.MustCompile(`[^=!<>~]=\s*(?:if|unless|case|begin|while|until)\b`)
	rbEndlessDefRe     = regexp.MustCompile(`^def\s+[^\n]*?\)\s*=[^=~>]|^def\s+[\w.?!]+\s*=[^=~>]`)
	rbDoRe             = regexp.MustCompile(`(?:^|[^.:@$\w])do\b`)
	rbEndRe            = regexp.MustCompile(`(?:^|[^.:@$\w])end\b`)
	rbTrailingDoRe     = regexp.MustCompile(`\s+do(?:\s*\|[^|\n]*\|)?\s*$`)
)

// countWord counts re's matches whose word is not a hash key (`end: 1`).
func countWord(re *regexp.Regexp, text string) int {
	n := 0
	for _, m := range re.FindAllStringIndex(text, -1) {
		if m[1] < len(text) && text[m[1]] == ':' && (m[1]+1 >= len(text) || text[m[1]+1] != ':') {
			continue
		}
		n++
	}
	return n
}

// rbCount returns how many blocks a statement opens and closes.
func rbCount(text string) (opens, ends int) {
	t := strings.TrimSpace(text)
	t = rbModifierPrefixRe.ReplaceAllString(t, "")
	dos := countWord(rbDoRe, t)
	if m := rbOpenRe.FindStringSubmatch(t); m != nil && !rbEndlessDefRe.MatchString(t) {
		rest := t[len(m[0]):]
		if !strings.HasPrefix(strings.TrimSpace(rest), ":") || strings.HasPrefix(strings.TrimSpace(rest), "::") {
			opens++
			if (m[1] == "while" || m[1] == "until" || m[1] == "for") && dos > 0 {
				dos--
			}
		}
	}
	if opens == 0 && rbAssignOpenRe.MatchString(t) {
		opens++
	}
	return opens + dos, countWord(rbEndRe, t)
}

func bracketDelta(code string) int {
	d := 0
	for i := 0; i < len(code); i++ {
		switch code[i] {
		case '(', '[', '{':
			d++
		case ')', ']', '}':
			d--
		}
	}
	return d
}

func continuesAfter(t string) bool {
	for _, suf := range []string{",", "\\", "&&", "||", "=>", "+", "="} {
		if strings.HasSuffix(t, suf) {
			return true
		}
	}
	return strings.HasSuffix(t, ".") && !strings.HasSuffix(t, "..")
}

// rbStatements splits f into logical statements in file order.
func rbStatements(f *rbFile) []rbStmt {
	n := len(f.lineStarts)
	bounds := func(i int) (int, int) {
		end := len(f.code)
		if i+1 < n {
			end = f.lineStarts[i+1] - 1
		}
		return f.lineStarts[i], end
	}
	nextLeadsWithDot := func(i int) bool {
		for ; i < n; i++ {
			s, e := bounds(i)
			t := strings.TrimSpace(f.code[s:e])
			if t == "" {
				continue
			}
			return len(t) > 1 && (t[0] == '.' && t[1] != '.' || strings.HasPrefix(t, "&."))
		}
		return false
	}
	var out []rbStmt
	for i := 0; i < n; {
		s, e := bounds(i)
		if strings.TrimSpace(f.code[s:e]) == "" {
			i++
			continue
		}
		if strings.TrimSpace(f.code[s:e]) == "__END__" {
			break
		}
		depth := 0
		j := i
		for {
			ls, le := bounds(j)
			line := f.code[ls:le]
			depth += bracketDelta(line)
			t := strings.TrimSpace(line)
			if (depth <= 0 && !continuesAfter(t) && !nextLeadsWithDot(j+1)) || j+1 >= n {
				break
			}
			j++
		}
		_, end := bounds(j)
		st := rbStmt{start: s, end: end}
		st.opens, st.ends = rbCount(f.code[s:end])
		out = append(out, st)
		i = j + 1
	}
	return out
}

// rbHead is the leading identifier of a statement, with the offset just past it.
func rbHead(f *rbFile, st rbStmt) (word string, end int) {
	i := st.start
	for i < st.end && (f.code[i] == ' ' || f.code[i] == '\t') {
		i++
	}
	j := i
	for j < st.end && (isIdentByte(f.code[j]) && f.code[j] != '$' || (f.code[j] == '?' || f.code[j] == '!') && j > i) {
		j++
	}
	return f.code[i:j], j
}

// rbArgs is a call's arguments: positional values, keywords and `key => value`
// pairs, as comment-free source text.
type rbArgs struct {
	pos   []string
	kw    map[string]string
	pairs [][2]string
}

var (
	rbKeywordRe = regexp.MustCompile(`^([A-Za-z_]\w*):(?:[^:]|$)`)
	rbSymbolRe  = regexp.MustCompile(`^:([A-Za-z_]\w*[?!]?)$`)
)

// rbCallArgs reads the arguments of the call whose head ends at headEnd:
// `get 'a', to: 'b' do` and `get('a', to: 'b')` alike.
func rbCallArgs(f *rbFile, st rbStmt, headEnd int) rbArgs {
	a := rbArgs{kw: map[string]string{}}
	from, to := headEnd, st.end
	if from < to && f.code[from] == '(' {
		if c := matchClose(f.code, from); c > 0 && c < to {
			from, to = from+1, c
		}
	} else if loc := rbTrailingDoRe.FindStringIndex(f.code[from:to]); loc != nil {
		to = from + loc[0]
	}
	for _, sp := range rbSplit(f.code, from, to) {
		for sp.start < sp.end && isSpace(f.sans[sp.start]) {
			sp.start++
		}
		for sp.end > sp.start && isSpace(f.sans[sp.end-1]) {
			sp.end--
		}
		code, sans := f.code[sp.start:sp.end], f.sans[sp.start:sp.end]
		if m := rbKeywordRe.FindStringSubmatch(code); m != nil {
			a.kw[m[1]] = strings.TrimSpace(sans[len(m[1])+1:])
			continue
		}
		if i := topLevelRocket(code); i >= 0 {
			key, val := strings.TrimSpace(sans[:i]), strings.TrimSpace(sans[i+2:])
			if m := rbSymbolRe.FindStringSubmatch(key); m != nil {
				a.kw[m[1]] = val
			} else {
				a.pairs = append(a.pairs, [2]string{key, val})
			}
			continue
		}
		a.pos = append(a.pos, sans)
	}
	return a
}

// rbSplit splits at top-level commas without trimming: a %i[...] literal is
// blank in the masked text, so trimming there would cut it off.
func rbSplit(code string, from, to int) []span {
	var out []span
	depth, last := 0, from
	for i := from; i < to; i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, span{last, i})
				last = i + 1
			}
		}
	}
	if last < to {
		out = append(out, span{last, to})
	}
	return out
}

func topLevelRocket(code string) int {
	depth := 0
	for i := 0; i+1 < len(code); i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '=':
			if depth == 0 && code[i+1] == '>' {
				return i
			}
		}
	}
	return -1
}

// rbStr reads a symbol or a plain string literal.
func rbStr(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if m := rbSymbolRe.FindStringSubmatch(s); m != nil {
		return m[1], true
	}
	if len(s) >= 3 && s[0] == ':' && (s[1] == '"' || s[1] == '\'') {
		s = s[1:]
	}
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		v := s[1 : len(s)-1]
		if strings.Contains(v, "#{") || strings.ContainsRune(v, '\\') {
			return "", false
		}
		return v, true
	}
	return "", false
}

var rbPercentListRe = regexp.MustCompile(`^%[iIwW][\[({<|!/](.*)[\])}>|!/]$`)

// rbList reads a list of names: `:a`, `[:a, :b]`, `%i[a b]`, `%w[a b]`.
func rbList(s string) ([]string, bool) {
	s = strings.TrimSpace(s)
	if m := rbPercentListRe.FindStringSubmatch(s); m != nil {
		return strings.Fields(m[1]), true
	}
	if v, ok := rbStr(s); ok {
		return []string{v}, true
	}
	if len(s) < 2 || s[0] != '[' || s[len(s)-1] != ']' {
		return nil, false
	}
	var out []string
	for _, part := range rbSplit(s, 1, len(s)-1) {
		v, ok := rbStr(s[part.start:part.end])
		if !ok {
			return nil, false
		}
		out = append(out, v)
	}
	return out, true
}

// rbCamel turns `admin/users_x` into `Admin::UsersX`.
func rbKey(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "_", ""))
}
