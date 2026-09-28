package engine

import (
	"regexp"
	"strings"
)

// XML external entity resolution (XXE, CWE-611) in Python.
//
// Python's standard XML parsers stopped resolving external entities by default
// in 3.7.1, and lxml stopped in 5.0. So the vulnerable condition is not
// "parses XML" -- that is nearly all XML handling, and almost all of it is
// safe -- but two things together: a parser someone switched external
// entities back ON, and a document the caller does not control. Either alone
// is not the finding:
//
//   - `parser.setFeature(feature_external_ges, True)` on a parser that only
//     ever reads a bundled file is a configuration smell, not an exploit;
//   - `minidom.parseString(request_body)` with the default parser is safe.
//
// The OWASP Benchmark for Python has exactly this split: seven of its safe
// cases enable external entities and parse a value that never carries the
// request. Reporting the configuration alone would flag them all.
//
// So XXE is a taint sink whose call name is synthetic. A per-file pass finds
// the locals bound to an entity-resolving parser; any parse call in a statement
// that reads one of them gains the chain `xxe_enabled_parser.parse`, which the
// catalog names as the sink. The taint engine then decides, as for every other
// sink, whether untrusted data reaches the call's arguments. Like import and
// receiver bindings, the chain is ADDED, so nothing that matched before can
// stop matching.
//
// Known limits: a parser configured in one function and used in another (a
// module-level parser is fine -- bindings are file-wide), a parser passed
// through a helper, and xml.etree's XMLParser, which has no entity switch.

// xxeSinkCall is the synthetic chain the catalog lists as the XXE sink.
const xxeSinkCall = "xxe_enabled_parser.parse"

var (
	// `p.setFeature(xml.sax.handler.feature_external_ges, True)` and the
	// parameter-entity twin, or the feature's URI spelled out.
	pySetExternalFeature = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\.setFeature\s*\(\s*(?:[\w.]*feature_external_[gp]es|["'][\w.:/-]*external-(?:general|parameter)-entities["'])\s*,\s*(?:True|1)\s*\)`)
	// `p = etree.XMLParser(..., resolve_entities=True, ...)` or with
	// no_network=False: lxml told to fetch what an entity names.
	pyEntityParser = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*=\s*[\w.]*XMLParser\s*\((.*)`)
	pyResolvesExt  = regexp.MustCompile(`\bresolve_entities\s*=\s*True\b|\bno_network\s*=\s*False\b`)
)

// xxeParseMethods are the calls that parse a document with a given parser:
// minidom.parse/parseString(src, parser), pulldom's, sax's, lxml's
// fromstring/XML/parse(src, parser), and the parser's own parse/feed.
var xxeParseMethods = map[string]bool{
	"parse": true, "parseString": true, "fromstring": true, "XML": true,
	"iterparse": true, "feed": true, "fromstringlist": true,
}

// pythonXXEParsers returns the locals bound to a parser that resolves external
// entities.
func pythonXXEParsers(content []byte) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(string(content), "\n") {
		if m := pySetExternalFeature.FindStringSubmatch(line); m != nil {
			out[m[1]] = true
			continue
		}
		if m := pyEntityParser.FindStringSubmatch(line); len(m) == 3 && pyResolvesExt.MatchString(m[2]) {
			out[m[1]] = true
		}
	}
	return out
}

// applyXXEParsers adds the XXE sink chain to every parse call made in a
// statement that reads an entity-resolving parser, carrying that call's
// argument record so the engine judges the document argument.
func applyXXEParsers(drafts []unitDraft, parsers map[string]bool) {
	if len(parsers) == 0 {
		return
	}
	for i := range drafts {
		for j := range drafts[i].stmts {
			st := &drafts[i].stmts[j]
			if !readsAny(st, parsers) {
				continue
			}
			for _, call := range st.calls {
				if !xxeParseMethods[lastDotted(call)] {
					continue
				}
				st.calls = append(st.calls, xxeSinkCall)
				if info, ok := st.sinkArgs[call]; ok {
					st.sinkArgs[xxeSinkCall] = info
				}
				break
			}
		}
	}
}

func readsAny(st *stmtDraft, names map[string]bool) bool {
	for _, r := range st.reads {
		if names[r] {
			return true
		}
	}
	for _, c := range st.calls {
		head, _, _ := strings.Cut(c, ".")
		if names[head] {
			return true
		}
	}
	return false
}

func lastDotted(chain string) string {
	if i := strings.LastIndexByte(chain, '.'); i >= 0 {
		return chain[i+1:]
	}
	return chain
}
