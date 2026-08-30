package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A `data:` URI payload is base64-encoded binary. Long alphanumeric runs
// inside it match the character-class-and-length patterns that many vendor
// secret rules use, but they are never credentials.
//
// inEmbeddedBlob already drops these — but only for languages lexctx can
// classify, so an inline image in an .html file slipped through entirely.
// nox's own server/dashboard/dashboard.html carries a base64 PNG logo on one
// 28KB line and reported 8 high-severity vendor "API key" findings from it,
// on every self-scan.
//
// The data-URI marker is lexically unambiguous in raw bytes, so this does not
// need a language at all.
func TestScan_DataURIPayloadIsNotASecret(t *testing.T) {
	// The payload must contain something the rules actually match, or this test
	// proves nothing.
	//
	// It used to be strings.Repeat("iVBORw0KGgo…", 40). That produces ZERO raw
	// matches — a repeated 44-character block has too little entropy for
	// SEC-161/162/163 and matches no provider pattern — so the assertion
	// "reported no findings" held whether or not inDataURIPayload did anything
	// at all. The filter under test was never once called. A test that passes
	// identically when the code it guards is deleted is the same defect as a
	// scan reporting an unexercised check as an all-clear, which is the thing
	// this repository exists to refuse; found while wiring the refiners to
	// record their reasoning (Track E1).
	//
	// An AWS access key ID embedded in the payload is matched by SEC-001, so
	// the filter is genuinely exercised — and rawMatchCount below pins that it
	// stays exercised rather than quietly reverting to asserting nothing.
	//
	// The "/" before the key is load-bearing. SEC-001 needs a word boundary
	// before AKIA, and a base64 run butted straight against it supplies none;
	// "/" is a legitimate base64 character, so the payload stays realistic
	// while the key remains matchable.
	payload := strings.Repeat("iVBORw0KGgoAAAANSUhEUgAAAHgAAABtCAYAAABqf6X6", 40) +
		"/AKIAIOSFODNN7EXAMPLE"
	html := `<!DOCTYPE html>
<html><body>
<img class="logo" src="data:image/png;base64,` + payload + `">
</body></html>`

	for _, tc := range []struct{ name, file string }{
		{"html", "dashboard.html"},
		{"css", "styles.css"},
		{"markdown", "README.md"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if n := rawMatchCount(t, tc.file, html); n == 0 {
				t.Fatal("the sample produces no raw matches, so the data: URI filter " +
					"is never called and this test asserts nothing")
			}
			got := scanStringForTest(t, tc.file, html)
			if len(got) != 0 {
				var ids []string
				for _, f := range got {
					ids = append(ids, f.RuleID)
				}
				t.Errorf("data: URI payload reported %d finding(s) %v; a base64 image is not a credential",
					len(got), ids)
			}
		})
	}
}

// rawMatchCount returns how many findings the rules produce before any filter
// runs. It exists so a suppression test can assert there was something to
// suppress.
func rawMatchCount(t *testing.T, name, content string) int {
	t.Helper()
	raw, err := NewAnalyzer().ScanFile(name, []byte(content))
	if err != nil {
		t.Fatalf("scan %s: %v", name, err)
	}
	return len(raw)
}

// The suppression must be scoped to the URI payload. A real credential
// elsewhere in the same file is still a leak, and dropping it would trade one
// false-positive class for a false negative — the worse of the two for a
// secret scanner.
func TestScan_SecretBesideDataURIStillReported(t *testing.T) {
	payload := strings.Repeat("iVBORw0KGgoAAAANSUhEUgAAAHgAAABtCAYAAABqf6X6", 40)
	html := `<html><body>
<img src="data:image/png;base64,` + payload + `">
<script>const token = "ghp_012345678901234567890123456789abcdef";</script>
</body></html>`

	got := scanStringForTest(t, "leaky.html", html)
	if len(got) == 0 {
		t.Fatal("a GitHub token next to a data: URI was not reported; the URI suppression is too broad")
	}
}

func scanStringForTest(t *testing.T, name, content string) []findingLite {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}

	a := NewAnalyzer()
	raw, err := a.ScanFile(name, []byte(content))
	if err != nil {
		t.Fatalf("scan %s: %v", name, err)
	}

	var out []findingLite
	for i := range raw {
		if inDataURIPayload([]byte(content), &raw[i]) {
			continue
		}
		out = append(out, findingLite{RuleID: raw[i].RuleID})
	}
	return out
}

type findingLite struct{ RuleID string }
