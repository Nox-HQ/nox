package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// cassette is the vcrpy shape, with a genuinely leaked key in the REQUEST
// headers and ordinary server data in the RESPONSE. The token below is a
// structurally valid OpenAI-style string built from a fixed run — it is not a
// key anyone issued, and it is here because the test is worthless without one.
func cassette() string {
	leaked := "sk-" + strings.Repeat("A9f2Kd", 8)
	return `interactions:
- request:
    body: '{"model": "text-embedding-ada-002"}'
    headers:
      accept:
      - application/json
      authorization:
      - Bearer ` + leaked + `
    method: POST
    uri: https://api.openai.com/v1/embeddings
  response:
    body:
      string: "{\"object\": \"list\", \"data\": [{\"embedding\": \"` +
		strings.Repeat("eM8FvBM/VTsslBQ70U5uvHkoKLsMMAw9BARUvAGpQLw3YJe8", 40) + `\"}]}"
    headers:
      Set-Cookie:
      - __cf_bm=` + strings.Repeat("pumYGlf1gsbVoFNTM1vh9Okj41SgxP3y65T5YWWPU1U", 2) + `-1736018539-1.0.1.1-x; path=/
      - _cfuvid=` + strings.Repeat("ZQ4hPbsx7T0mWiaR3gKcVndEuXyfLA1jt", 3) + `; path=/
    status:
      code: 200
      message: OK
version: 1
`
}

// scanAt runs the analyzer's real entry point with a nested reported path but
// a flat file on disk, because one test below depends on the directory NAME.
//
// ScanFile is the raw engine and runs NO refiner — every precision filter in
// this analyzer, this one included, lives in ScanArtifacts. A test calling
// ScanFile therefore passes whatever the gate does, which is how the first
// version of this file reported a gate working that had never run.
func scanAt(t *testing.T, name, body string) []findings.Finding {
	t.Helper()
	dir := t.TempDir()
	abs := filepath.Join(dir, filepath.Base(name))
	if err := os.WriteFile(abs, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	fs, err := NewAnalyzer().ScanArtifacts(context.Background(),
		[]discovery.Artifact{{Path: name, AbsPath: abs, Type: discovery.Config}})
	if err != nil {
		t.Fatal(err)
	}
	return fs.Findings()
}

// TestARecordedRequestCredentialIsStillReported is the test that makes the rest
// of this file safe. vcrpy does not filter headers unless `filter_headers` is
// configured, and forgetting to configure it is a well-known way to commit a
// live key. Suppressing a whole cassette would trade a pile of false positives
// for exactly that false negative, so the gate covers the response block only —
// and this asserts the request block still reports.
func TestARecordedRequestCredentialIsStillReported(t *testing.T) {
	if len(scanAt(t, "tests/cassettes/test_embeddings.yaml", cassette())) == 0 {
		t.Fatal("the leaked authorization header in the REQUEST block was not reported; " +
			"the response-side gate has swallowed the one finding a cassette exists to surface")
	}
}

// TestRecordedTrafficIsNotACredential. The embedding vector and the two
// Cloudflare cookies are what the wire carried; nobody in this repository can
// rotate them. Measured on crewAI at 1.15.21, 540 SEC-161/SEC-162 findings were
// inside cassettes and not one was a credential the project held.
func TestRecordedTrafficIsNotACredential(t *testing.T) {
	body := cassette()
	got := scanAt(t, "tests/cassettes/test_embeddings.yaml", body)
	lines := strings.Split(body, "\n")
	// SEC-082 matches from the `authorization:` key through the value on the
	// next line, so the reported line is the key's.
	authLine := 0
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "authorization:") {
			authLine = i + 1
			break
		}
	}
	if authLine == 0 {
		t.Fatal("fixture has no authorization header")
	}
	for _, f := range got {
		if f.Location.StartLine != authLine {
			t.Errorf("%s reported at line %d (%q), but the only credential this "+
				"repository holds is the request authorization header at line %d",
				f.RuleID, f.Location.StartLine, f.Message, authLine)
		}
	}
}

// TestCredentialSpansAreTheRequestHeadersAndURI states the boundary directly.
// A cookie is excluded in either direction: in a recording it is a session the
// server issued, already expired, and not something anyone here can rotate.
func TestCredentialSpansAreTheRequestHeadersAndURI(t *testing.T) {
	doc := []byte("interactions:\n" +
		"- request:\n" +
		"    headers:\n" +
		"      authorization:\n" +
		"      - Bearer AAA\n" +
		"      cookie:\n" +
		"      - __cf_bm=BBB\n" +
		"    uri: https://api.example.com/v1?k=CCC\n" +
		"    body: '{\"prompt\": \"DDD\"}'\n" +
		"  response:\n" +
		"    body:\n" +
		"      string: EEE\n")
	spans := credentialBearingSpans(doc)
	find := func(needle string) bool {
		i := bytes.Index(doc, []byte(needle))
		if i < 0 {
			t.Fatalf("fixture lacks %q", needle)
		}
		return inSpan(spans, i)
	}
	for needle, want := range map[string]bool{
		"AAA": true,  // request authorization header
		"CCC": true,  // request URI
		"BBB": false, // request cookie: a recorded session, not a held credential
		"DDD": false, // request body: the prompt that was sent
		"EEE": false, // response body
	} {
		if got := find(needle); got != want {
			t.Errorf("%q in a credential-bearing span = %v, want %v", needle, got, want)
		}
	}
}

// A rule that encodes a vendor format has established what it found, so it is
// left to fire anywhere in a recording — an OAuth client_secret in a recorded
// token request is a real leak and sits in the request BODY.
func TestAVendorFormatRuleStillFiresInsideARecording(t *testing.T) {
	doc := "interactions:\n" +
		"- request:\n" +
		"    uri: https://api.example.com/oauth/token\n" +
		"    body: '{\"client_secret\": \"ghp_" + strings.Repeat("Ab3xK9", 6) + "\"}'\n" +
		"  response:\n" +
		"    body:\n" +
		"      string: ok\n"
	if len(scanAt(t, "tests/cassettes/token.yaml", doc)) == 0 {
		t.Error("a provider-format token in a recorded request body was not reported; " +
			"the entropy gate has been applied to rules it does not cover")
	}
}

// TestGatingReadsTheDocumentNotThePath. A cassette is conventionally under
// tests/cassettes/, but that is a convention. Gating on the path would miss
// cassettes stored elsewhere and — the expensive direction — suppress every
// genuine secret in any directory somebody named that.
func TestGatingReadsTheDocumentNotThePath(t *testing.T) {
	if !isHTTPRecording("fixtures/recorded/embeddings.yaml", []byte(cassette())) {
		t.Error("a cassette outside tests/cassettes/ was not recognised")
	}
	notACassette := "response: 200\napi_key: qW7zR2xLp9TvBn4KdM1sYhJc6UaG3eFo\n"
	if isHTTPRecording("tests/cassettes/config.yaml", []byte(notACassette)) {
		t.Error("an ordinary YAML file under tests/cassettes/ was treated as a recording")
	}
	if len(scanAt(t, "tests/cassettes/config.yaml", notACassette)) == 0 {
		t.Error("a hardcoded key in an ordinary YAML file under tests/cassettes/ was not " +
			"reported — the gate is keying on the directory name")
	}
}

// TestEachInteractionIsBounded. Both the request block and the headers block
// inside it are bounded by indentation. Getting either wrong in the generous
// direction is the expensive one: a span running past its block would mark
// recorded traffic as credential-bearing, and a block ending early would mark
// the next interaction's authorization header as traffic.
func TestEachInteractionIsBounded(t *testing.T) {
	doc := []byte("interactions:\n" +
		"- request:\n" +
		"    headers:\n" +
		"      authorization:\n" +
		"      - Bearer FIRST\n" +
		"    uri: https://a\n" +
		"  response:\n" +
		"    body:\n" +
		"      string: RESPONSEDATA\n" +
		"- request:\n" +
		"    headers:\n" +
		"      authorization:\n" +
		"      - Bearer SECOND\n" +
		"    uri: https://b\n")
	spans := credentialBearingSpans(doc)
	for needle, want := range map[string]bool{
		"FIRST":        true,
		"SECOND":       true,
		"https://a":    true,
		"https://b":    true,
		"RESPONSEDATA": false,
	} {
		i := bytes.Index(doc, []byte(needle))
		if i < 0 {
			t.Fatalf("fixture lacks %q", needle)
		}
		if got := inSpan(spans, i); got != want {
			t.Errorf("%q credential-bearing = %v, want %v", needle, got, want)
		}
	}
}

// TestAHeaderIsAListNotAString is the false negative that the response-side
// gate would otherwise have hidden.
//
// A credential written inline was reported; the identical credential written
// as a one-element YAML sequence was not. HTTP headers may repeat, so every
// recorded exchange, and most header maps anywhere, write them as a list:
//
//	authorization:
//	- Bearer sk-proj-…
//
// SEC-082 required only whitespace between the key and `Bearer`, and Go's `\s`
// crosses a newline but not the sequence dash. So nox read every cassette in
// the corpus and could not have reported the one thing worth finding in one —
// and adding the response-side gate first would have made cassettes quieter
// while leaving them unchecked, which is the same reading either way.
func TestAHeaderIsAListNotAString(t *testing.T) {
	tok := "sk-proj-7QxL2mVn8RtYw4ZbKd1PcJhF6sAeG3oU9iTr5yNqXvB0"
	for name, src := range map[string]string{
		"inline":            "authorization: Bearer " + tok + "\n",
		"sequence":          "    headers:\n      authorization:\n      - Bearer " + tok + "\n",
		"sequence-inline":   "    headers:\n      authorization: [Bearer " + tok + "]\n",
		"sequence-basic":    "    headers:\n      authorization:\n      - Basic dXNlcjpwYXNzd29yZDEyMw==\n",
		"sequence-in-quote": "      authorization:\n      - \"Bearer " + tok + "\"\n",
	} {
		var saw bool
		for _, f := range scanAt(t, "cfg.yaml", src) {
			if f.RuleID == "SEC-082" || f.RuleID == "SEC-083" {
				saw = true
			}
		}
		if !saw {
			t.Errorf("%s: a hardcoded authorization header was not reported:\n%s", name, src)
		}
	}
}

// TestTheMarkerAloneDoesNotGateAFile. The gate confines the entropy rules to
// the request side of a recording, so a document carrying the marker and no
// request block would have no credential-bearing span at all — and every
// high-entropy value in it would be silently withheld. `interactions:` is a
// plausible key in an ordinary configuration file, so the structure is required
// as well as the name.
func TestTheMarkerAloneDoesNotGateAFile(t *testing.T) {
	notARecording := "interactions:\n" +
		"  slack:\n" +
		"    signing_secret: qW7zR2xLp9TvBn4KdM1sYhJc6UaG3eFo\n"
	if isHTTPRecording("config.yaml", []byte(notARecording)) {
		t.Error("a config file using the key `interactions:` was treated as a recording")
	}
	if len(scanAt(t, "config.yaml", notARecording)) == 0 {
		t.Error("a hardcoded secret in a config file using the key `interactions:` was " +
			"not reported — the gate fires on the marker without the structure")
	}
}

// TestADecodedMatchIsGatedToo. A cassette's request body is frequently base64:
// crewAI's is an OpenTelemetry protobuf payload, several thousand characters of
// it per interaction. nox decodes base64 segments and scans the plaintext, then
// relocates the finding back onto the encoding segment — and that path adds its
// results without going through the refiners at all, so the gate missed 107
// findings on crewAI until this was wired.
func TestADecodedMatchIsGatedToo(t *testing.T) {
	// A JSON object with a high-entropy value, base64-encoded, sitting in the
	// request body exactly as a telemetry payload does.
	payload := base64.StdEncoding.EncodeToString([]byte(
		`{"key": "` + strings.Repeat("7a9ec7cb122f512c1a5709e1d48aa2", 3) + `"}`))
	doc := "interactions:\n" +
		"- request:\n" +
		"    uri: https://telemetry.example.com/v1/traces\n" +
		"    body: !!binary |\n" +
		"      " + payload + "\n" +
		"  response:\n" +
		"    body:\n" +
		"      string: ok\n"
	for _, f := range scanAt(t, "tests/cassettes/telemetry.yaml", doc) {
		if entropyOnlyRules[f.RuleID] {
			t.Errorf("%s reported high-entropy bytes decoded out of a recorded request "+
				"body at line %d; the decode path bypasses the gate",
				f.RuleID, f.Location.StartLine)
		}
	}

	// The control, without which the assertion above passes for a fixture that
	// simply never produced a decoded finding. The same bytes outside a
	// recording must still be reported.
	var fired bool
	for _, f := range scanAt(t, "telemetry.yaml", strings.Replace(doc, "interactions:", "items:", 1)) {
		if entropyOnlyRules[f.RuleID] {
			fired = true
		}
	}
	if !fired {
		t.Fatal("the fixture produces no decoded entropy finding even outside a recording, " +
			"so the assertion above cannot tell the gate from an empty scan")
	}
}
