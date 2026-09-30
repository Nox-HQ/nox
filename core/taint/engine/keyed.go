package engine

import (
	"regexp"
	"strings"
)

// Key-sensitive container taint for literal keys.
//
// Container taint is field-insensitive: `m['keyB'] = param` taints the whole
// of m, so `bar = m['keyA']` -- a key that never held the value -- reads as
// tainted. On the OWASP Benchmarks this is the largest false-positive family
// left after branch pruning (map keys, configparser sections), and real code
// builds small dicts and maps the same way.
//
// The fix is a per-file rewrite before extraction: a container whose every use
// is a recognised literal-keyed store or read is split into one variable per
// key -- `m['keyB']` becomes `m__nox_keyB` -- so the engine's ordinary
// variable tracking keeps the keys apart.
//
// It applies ONLY where that is provably the whole story. A container
// qualifies when it is created empty (`{}`, `dict()`, a ConfigParser, `new
// HashMap<>()`) and every other occurrence of its name is a literal-keyed
// store or read. Anything else -- passing it whole, iterating it, a
// non-literal key, update/putAll, a non-empty initializer -- disqualifies it,
// and it keeps today's whole-container taint. So a flow the field-insensitive
// model finds can only be lost where the key-sensitive one proves it cannot
// happen.

type keyedLang struct {
	init  *regexp.Regexp // `m = {}`: group 1 is the name
	store []*regexp.Regexp
	read  []*regexp.Regexp
	// other allowed uses that neither store nor read (`conf.add_section('s')`)
	allowed []*regexp.Regexp
}

// Every pattern's group "name" is the container; "key" (and "sec") the
// literal key text in the raw view; "val" the stored value.
var keyedPython = keyedLang{
	init: regexp.MustCompile(`^\s*(?P<name>[A-Za-z_]\w*)\s*=\s*(?:\{\s*\}|dict\s*\(\s*\)|(?:configparser\s*\.\s*)?(?:Raw)?ConfigParser\s*\(\s*\))\s*$`),
	store: []*regexp.Regexp{
		regexp.MustCompile(`^(?P<pre>\s*)(?P<name>[A-Za-z_]\w*)\s*\[\s*(?P<q>['"])(?P<key>[^'"\\]*)['"]\s*\]\s*=(?P<val>[^=].*)$`),
		regexp.MustCompile(`^(?P<pre>\s*)(?P<name>[A-Za-z_]\w*)\s*\.\s*set\s*\(\s*['"](?P<sec>[^'"\\]*)['"]\s*,\s*['"](?P<key>[^'"\\]*)['"]\s*,(?P<val>.*)\)\s*$`),
	},
	read: []*regexp.Regexp{
		regexp.MustCompile(`\b(?P<name>[A-Za-z_]\w*)\s*\[\s*['"](?P<key>[^'"\\]*)['"]\s*\]`),
		regexp.MustCompile(`\b(?P<name>[A-Za-z_]\w*)\s*\.\s*get\s*\(\s*['"](?P<sec>[^'"\\]*)['"]\s*,\s*['"](?P<key>[^'"\\]*)['"]\s*\)`),
		regexp.MustCompile(`\b(?P<name>[A-Za-z_]\w*)\s*\.\s*get\s*\(\s*['"](?P<key>[^'"\\]*)['"]\s*\)`),
	},
	allowed: []*regexp.Regexp{
		regexp.MustCompile(`^\s*(?P<name>[A-Za-z_]\w*)\s*\.\s*add_section\s*\(\s*['"][^'"\\]*['"]\s*\)\s*$`),
	},
}

var keyedJava = keyedLang{
	init: regexp.MustCompile(`^\s*(?:final\s+)?(?:[\w.]+\s*(?:<[^;=]*>)?\s+)?(?P<name>[A-Za-z_]\w*)\s*=\s*new\s+(?:java\s*\.\s*util\s*\.\s*)?(?:HashMap|LinkedHashMap|TreeMap|Hashtable|ConcurrentHashMap|Properties)\s*(?:<[^;()]*>)?\s*\(\s*\)\s*;?\s*$`),
	store: []*regexp.Regexp{
		regexp.MustCompile(`^(?P<pre>\s*)(?P<name>[A-Za-z_]\w*)\s*\.\s*(?:put|setProperty)\s*\(\s*"(?P<key>[^"\\]*)"\s*,(?P<val>.*)\)\s*;?\s*$`),
	},
	read: []*regexp.Regexp{
		regexp.MustCompile(`\b(?P<name>[A-Za-z_]\w*)\s*\.\s*(?:get|getProperty)\s*\(\s*"(?P<key>[^"\\]*)"\s*\)`),
	},
}

func keyedFor(lang langKind) *keyedLang {
	switch lang {
	case langPython:
		return &keyedPython
	case langJava:
		return &keyedJava
	}
	return nil
}

var keyedIdentChar = regexp.MustCompile(`[^A-Za-z0-9_]`)

// keyedName is the synthetic variable for one key of one container.
func keyedName(name, sec, key string) string {
	k := key
	if sec != "" {
		k = sec + "__" + key
	}
	return name + "__nox_" + keyedIdentChar.ReplaceAllString(k, "_")
}

func group(re *regexp.Regexp, m []int, s, g string) string {
	i := re.SubexpIndex(g)
	if i < 0 || m[2*i] < 0 {
		return ""
	}
	return s[m[2*i]:m[2*i+1]]
}

// rewriteKeyedContainers splits qualifying containers into per-key variables.
func rewriteKeyedContainers(lang langKind, lines []logicalLine) {
	kl := keyedFor(lang)
	if kl == nil {
		return
	}
	eligible := keyedEligible(kl, lines)
	if len(eligible) == 0 {
		return
	}
	for i := range lines {
		lines[i] = rewriteKeyedLine(kl, lines[i], eligible)
	}
}

// keyedEligible returns the containers every occurrence of which is an empty
// initializer, a literal-keyed store or read, or an allowed no-op.
func keyedEligible(kl *keyedLang, lines []logicalLine) map[string]bool {
	inits := map[string]int{}
	bad := map[string]bool{}
	accounted := map[string]int{}
	for _, ll := range lines {
		raw := ll.raw
		if m := kl.init.FindStringSubmatch(raw); m != nil {
			inits[m[kl.init.SubexpIndex("name")]]++
			accounted[m[kl.init.SubexpIndex("name")]]++
			continue
		}
		matched := false
		for _, re := range kl.allowed {
			if m := re.FindStringSubmatch(raw); m != nil {
				accounted[m[re.SubexpIndex("name")]]++
				matched = true
			}
		}
		if matched {
			continue
		}
		for _, re := range kl.store {
			if m := re.FindStringSubmatchIndex(raw); m != nil {
				accounted[group(re, m, raw, "name")]++
				raw = raw[:m[0]] + strings.Repeat(" ", m[1]-m[0]-len(group(re, m, raw, "val"))) + group(re, m, raw, "val")
				break
			}
		}
		for _, re := range kl.read {
			for _, m := range re.FindAllStringSubmatch(raw, -1) {
				accounted[m[re.SubexpIndex("name")]]++
			}
		}
	}
	// Every occurrence of the name, anywhere, must have been accounted for.
	total := map[string]int{}
	for name := range inits {
		word := regexp.MustCompile(`(?:^|[^\w.])` + regexp.QuoteMeta(name) + `\b`)
		for _, ll := range lines {
			total[name] += len(word.FindAllStringIndex(ll.code, -1))
		}
	}
	out := map[string]bool{}
	for name, n := range inits {
		if n == 1 && !bad[name] && total[name] == accounted[name] {
			out[name] = true
		}
	}
	return out
}

// rewriteKeyedLine rewrites one line's stores and reads of eligible
// containers. A store becomes `name__nox_key = value`; a read becomes the
// variable. Both views receive the same text, so they stay aligned.
func rewriteKeyedLine(kl *keyedLang, ll logicalLine, eligible map[string]bool) logicalLine {
	for _, re := range kl.store {
		m := re.FindStringSubmatchIndex(ll.raw)
		if m == nil {
			continue
		}
		name := group(re, m, ll.raw, "name")
		if !eligible[name] {
			continue
		}
		vi := re.SubexpIndex("val")
		valRaw := ll.raw[m[2*vi]:m[2*vi+1]]
		valCode := valRaw
		if m[2*vi+1] <= len(ll.code) {
			valCode = ll.code[m[2*vi]:m[2*vi+1]]
		}
		head := group(re, m, ll.raw, "pre") + keyedName(name, group(re, m, ll.raw, "sec"), group(re, m, ll.raw, "key")) + " ="
		ll = logicalLine{line: ll.line, raw: head + valRaw, code: head + valCode}
		break
	}
	for _, re := range kl.read {
		for {
			m := re.FindStringSubmatchIndex(ll.raw)
			found := false
			for m != nil {
				name := group(re, m, ll.raw, "name")
				if eligible[name] {
					found = true
					break
				}
				// Look past a non-eligible match.
				next := re.FindStringSubmatchIndex(ll.raw[m[1]:])
				if next == nil {
					m = nil
					break
				}
				for j := range next {
					if next[j] >= 0 {
						next[j] += m[1]
					}
				}
				m = next
			}
			if !found {
				break
			}
			v := keyedName(group(re, m, ll.raw, "name"), group(re, m, ll.raw, "sec"), group(re, m, ll.raw, "key"))
			ll.raw = ll.raw[:m[0]] + v + ll.raw[m[1]:]
			if m[1] <= len(ll.code) {
				ll.code = ll.code[:m[0]] + v + ll.code[m[1]:]
			}
		}
	}
	return ll
}
