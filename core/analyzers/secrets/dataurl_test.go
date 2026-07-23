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
	// A payload chosen to contain the runs that tripped SEC-629 / SEC-692 on
	// the real dashboard: mixed-case alphanumerics of credential-like length.
	payload := strings.Repeat("iVBORw0KGgoAAAANSUhEUgAAAHgAAABtCAYAAABqf6X6", 40)
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
