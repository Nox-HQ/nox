package secrets

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// TestDedupMatchesReference holds dedupBySpecificity to the algorithm it
// replaced (dedup_reference_test.go) on thousands of seeded finding sets.
// The rewrite changed how far each anchor looks, not what it decides, so the
// survivors, their order and every suppression (dropped, survivor, reason)
// must be identical -- with and without the content pinned.
//
// The sets are built to exercise every branch of pass 1 and pass 2: owned
// tokens of several providers, the JWT owners including SEC-952, name-bound
// and URL-shaped non-owners whose claimed value is or is not the token,
// generic rules, co-canonical owners, and spans that continue onto later
// lines.
func TestDedupMatchesReference(t *testing.T) {
	spec := NewAnalyzer().spec
	ruleIDs := []string{
		"SEC-371", "SEC-952", "SEC-100", "SEC-105", "SEC-084", "SEC-251", // JWT owners and aliases
		"SEC-003", "SEC-017", "SEC-216", // GitHub
		"SEC-001", "SEC-508", // AWS, co-canonical
		"SEC-018", "SEC-030", "SEC-023", "SEC-007", // GitLab, Stripe, Slack, GCP
		"SEC-073", "SEC-085", "SEC-082", "SEC-183", "SEC-005", "SEC-469", // URL / name-bound non-owners
		"SEC-161", "SEC-162", "SEC-163", // generic
	}
	r := rand.New(rand.NewSource(827))
	cases := 4000
	if testing.Short() {
		cases = 400
	}
	for c := 0; c < cases; c++ {
		content, lines := equivalenceContent(r)
		in := equivalenceFindings(r, lines, ruleIDs)

		wantOut, wantDropped := refDedupBySpecificity(cloneFindings(in), spec, content)
		gotOut, gotDropped := dedupBySpecificity(cloneFindings(in), spec, content)
		if !reflect.DeepEqual(gotOut, wantOut) || !reflect.DeepEqual(gotDropped, wantDropped) {
			t.Fatalf("case %d diverges from the reference\ncontent:\n%s\nfindings: %+v\nwant out %v dropped %+v\ngot  out %v dropped %+v",
				c, content, in, ruleIDsOf(wantOut), wantDropped, ruleIDsOf(gotOut), gotDropped)
		}

		release := lexctx.Pin(content)
		pinnedOut, pinnedDropped := dedupBySpecificity(cloneFindings(in), spec, content)
		release()
		if !reflect.DeepEqual(pinnedOut, wantOut) || !reflect.DeepEqual(pinnedDropped, wantDropped) {
			t.Fatalf("case %d: pinned content diverges from the reference", c)
		}
	}
}

func cloneFindings(in []findings.Finding) []findings.Finding {
	return append([]findings.Finding(nil), in...)
}

// equivalenceContent is a few lines built from the shapes dedup reasons
// about: owned tokens, bindings, Authorization headers, URLs with a password
// and a token in the query, and plain text.
func equivalenceContent(r *rand.Rand) (content []byte, lines []string) {
	tok := func() string {
		switch r.Intn(7) {
		case 0:
			return "ghp_" + seededBody(r.Int63(), "abcdefghijklmnopqrstuvwxyz0123456789", 36)
		case 1:
			return "AKIA" + seededBody(r.Int63(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)
		case 2:
			return seededJWT(r.Int63())
		case 3:
			return scalingJWT(r, true)
		case 4:
			return "glpat-" + seededBody(r.Int63(), "abcdefghijklmnopqrstuvwxyz0123456789", 20)
		case 5:
			return "xoxb-" + seededBody(r.Int63(), "0123456789", 12) + "-" + seededBody(r.Int63(), "abcdefghij", 24)
		default:
			return seededBody(r.Int63(), "abcdefghijklmnopqrstuvwxyz0123456789", 32)
		}
	}
	shapes := []func() string{
		func() string { return "KEY=" + tok() },
		func() string { return `value = "` + tok() + `"` },
		func() string {
			return `curl -H "Accept: application/json" -H "Authorization: Bearer ` + tok() + `" https://api.example.com`
		},
		func() string { return "postgres://svc:" + tok() + "@db.internal:5432/app" },
		func() string { return "postgres://svc:hunter2pw@db.internal:5432/app?token=" + tok() },
		func() string { return "Token: " + tok() + " and " + tok() },
		func() string { return "nothing to see here" },
	}
	n := 1 + r.Intn(6)
	lines = make([]string, n)
	for i := range lines {
		lines[i] = shapes[r.Intn(len(shapes))]()
	}
	return []byte(strings.Join(lines, "\n") + "\n"), lines
}

// equivalenceFindings places findings at random spans, biased to overlap:
// several share a line and most start near a token or binding.
func equivalenceFindings(r *rand.Rand, lines, ruleIDs []string) []findings.Finding {
	n := 1 + r.Intn(12)
	out := make([]findings.Finding, n)
	for i := range out {
		li := r.Intn(len(lines))
		line := lines[li]
		start := 1
		if len(line) > 1 {
			// Prefer the value after a binding or a scheme, where tokens sit.
			if k := strings.LastIndexAny(line, "=: "); k >= 0 && r.Intn(3) > 0 {
				start = k + 2
			} else {
				start = 1 + r.Intn(len(line))
			}
		}
		end := start + 1 + r.Intn(len(line)+2)
		endLine := li + 1
		if r.Intn(10) == 0 && li+1 < len(lines) { // a span that continues onto the next line
			endLine = li + 2
			end = 1 + r.Intn(len(lines[li+1])+1)
		}
		out[i] = findings.Finding{
			RuleID: ruleIDs[r.Intn(len(ruleIDs))],
			Location: findings.Location{
				FilePath:    "f.py",
				StartLine:   li + 1,
				StartColumn: start,
				EndLine:     endLine,
				EndColumn:   end,
			},
			Message: fmt.Sprintf("m%d", i),
		}
	}
	return out
}

// refInDataURIPayload is inDataURIPayload as it was before the file's data:
// URI offsets were computed once (68cf661), the oracle for the test below.
func refInDataURIPayload(content []byte, f *findings.Finding) bool {
	start := lexctx.LineColToOffset(content, f.Location.StartLine, f.Location.StartColumn)
	if start < 0 || start > len(content) {
		return false
	}
	for off := 0; off < start; {
		rel := bytes.Index(content[off:], dataURIScheme)
		if rel < 0 {
			return false
		}
		uriStart := off + rel
		if uriStart >= start {
			return false
		}
		payloadStart, ok := base64PayloadStart(content, uriStart)
		if !ok {
			off = uriStart + len(dataURIScheme)
			continue
		}
		if start >= payloadStart && start < payloadEnd(content, payloadStart) {
			return true
		}
		off = uriStart + len(dataURIScheme)
	}
	return false
}

func TestDataURIPayloadMatchesReference(t *testing.T) {
	r := rand.New(rand.NewSource(828))
	pieces := []string{"data:", "data:image/png;base64,", ";base64,", "iVBORw0KGgoAAAANSUhEUg", "AAAA==", " ", "\n", `"`, "x", "src=", "data:text/plain,hi"}
	hits := 0
	for c := 0; c < 3000; c++ {
		var b strings.Builder
		for n := r.Intn(25); n >= 0; n-- {
			b.WriteString(pieces[r.Intn(len(pieces))])
		}
		content := []byte(b.String())
		lines := strings.Split(string(content), "\n")
		starts := dataURIStarts(content)
		for q := 0; q < 20; q++ {
			li := r.Intn(len(lines))
			f := &findings.Finding{Location: findings.Location{StartLine: li + 1, StartColumn: 1 + r.Intn(len(lines[li])+2)}}
			want := refInDataURIPayload(content, f)
			if got := inDataURIPayloadAt(content, starts, f); got != want {
				t.Fatalf("content %q at %d:%d: got %v, reference %v", content, f.Location.StartLine, f.Location.StartColumn, got, want)
			}
			if want {
				hits++
			}
		}
	}
	if hits < 100 {
		t.Fatalf("only %d payload hits; the generator no longer exercises the true branch", hits)
	}
}
