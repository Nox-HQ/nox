package secrets

import (
	"strings"
	"testing"
)

// bindingRules are the nine vendor rules whose claim is "a value bound to a
// name starting with the vendor's word" (bcb182c). Each accepts a run of N
// letters and digits and, until this change, nothing about where that run
// ends — so the first N characters of any longer code identifier qualified.
var bindingRules = map[string]struct {
	word string
	n    int
}{
	"SEC-540": {"namecheap", 32}, "SEC-590": {"wave", 32}, "SEC-616": {"fcm", 32},
	"SEC-629": {"lob", 32}, "SEC-635": {"salesforce", 32}, "SEC-652": {"jenkins", 20},
	"SEC-659": {"split", 32}, "SEC-664": {"heap", 32}, "SEC-665": {"fullstory", 20},
}

func reports(t *testing.T, name, src, id string) bool {
	t.Helper()
	for _, f := range scanOne(t, name, src) {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// A value that is a credential ends: at a quote, whitespace, the end of the
// line, or a separator. Each rule still reports one, in every shape a
// credential is written in, including a value longer than the rule's N.
func TestABoundCredentialIsStillReported(t *testing.T) {
	for id, r := range bindingRules {
		v := strings.Repeat("a1B2c3D4e5", 5)[:r.n]
		long := v + "Xy9"
		for _, src := range []struct{ name, body string }{
			{"config.env", strings.ToUpper(r.word) + "_API_KEY=" + v + "\n"},
			{"config.yaml", r.word + "_token: " + v + "\n"},
			{"settings.py", r.word + "_key = \"" + v + "\"\n"},
			{"settings.py", r.word + "_key = '" + long + "'\n"},
			{"app.json", "{\"" + r.word + "_key\": \"" + v + "\"}\n"},
			{"call.py", "client(" + r.word + "_key=\"" + v + "\", x=1)\n"},
		} {
			if !reports(t, src.name, src.body, id) {
				t.Errorf("%s did not report %q in %s", id, src.body, src.name)
			}
		}
	}
}

// A code identifier is not a credential. `splitter =
// SemanticDoubleMergingSplitterNodeParser(` in llama_index's tests reported
// SEC-659 "Split API Key" five times: `splitter` begins with `split`, and the
// class name's first 32 characters are 32 letters. An identifier goes on into
// a call, an attribute or an index; a credential does not.
func TestAnIdentifierIsNotABoundCredential(t *testing.T) {
	for id, r := range bindingRules {
		ident := "Semantic" + strings.Repeat("DoubleMerging", 3)
		for _, body := range []string{
			r.word + "ter = " + ident + "(\n",
			r.word + "ter = " + ident + ".from_defaults(\n",
			r.word + "_map: " + ident + "[0]\n",
		} {
			if reports(t, "code.py", body, id) {
				t.Errorf("%s reported the identifier in %q", id, body)
			}
		}
	}
}
