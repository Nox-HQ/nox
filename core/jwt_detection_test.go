package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
)

// A published example JWT (RFC 7519 / jwt.io HS256). Not a credential — its
// signing key is public — but structurally a real token, so it is the right
// fixture: a JWT nox must detect, and one whose structure verifies.
const exampleJWT = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.` +
	`eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.` +
	`SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`

func scanJWT(t *testing.T, source string) *ScanResult {
	t.Helper()
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.py"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return res
}

// TestAHardcodedJWTIsDetected is the regression for a silent false negative.
//
// A full JWT runs to hundreds of bytes, and the data-blob refiner dropped any
// string over 96 bytes as an opaque base64 payload — so a hardcoded JWT
// assigned to a variable was silently discarded. The threshold's own comment
// reasoned about "a JWT header segment" and missed that the whole token is
// long. A credential class nox could not see at all.
func TestAHardcodedJWTIsDetected(t *testing.T) {
	res := scanJWT(t, `API_JWT = "`+exampleJWT+`"`+"\n")
	if len(res.Findings.Findings()) == 0 {
		t.Error("a hardcoded JWT produced no finding; it was dropped as a data blob, " +
			"which is how nox silently missed an entire credential class")
	}
}

// TestADetectedJWTCarriesADeterministicClaim. The whole point of verifying the
// structure is that the finding rests on more than a pattern match. A JWT
// finding must carry a KindStatic claim, not only heuristics.
func TestADetectedJWTCarriesADeterministicClaim(t *testing.T) {
	res := scanJWT(t, `API_JWT = "`+exampleJWT+`"`+"\n")
	var found bool
	for _, f := range res.Findings.Findings() {
		for _, c := range res.Reasoning.About(SubjectForFinding(f)).Claims {
			if c.Kind == evidence.KindStatic && !c.Refutes() && strings.Contains(c.Statement, "JWT") {
				found = true
			}
		}
	}
	if !found {
		t.Error("a detected JWT carries no deterministic claim that it decodes as one; " +
			"the finding rests on the pattern alone, which is what verification was for")
	}
}

// TestOverlappingJWTRulesCollapseToOne. Three rules match a JWT, and they are
// one credential class. Surfacing the JWT must not surface it three times.
func TestOverlappingJWTRulesCollapseToOne(t *testing.T) {
	res := scanJWT(t, `API_JWT = "`+exampleJWT+`"`+"\n")
	active := res.Findings.ActiveFindings()
	jwtFindings := 0
	for _, f := range active {
		if strings.Contains(strings.ToLower(f.Message), "jwt") ||
			strings.Contains(strings.ToLower(f.Message), "json web token") {
			jwtFindings++
		}
	}
	if jwtFindings > 1 {
		t.Errorf("one JWT produced %d findings; the overlapping rules did not collapse "+
			"to a canonical owner", jwtFindings)
	}
}

// TestAJWTLookalikeIsNotDetectedAsOne. A long base64 string that is NOT a JWT —
// a real data blob — must still be dropped. The structural exception must not
// become a hole through which every long base64 string re-enters.
func TestAJWTLookalikeIsNotDetectedAsOne(t *testing.T) {
	// A data URI: the exact false-positive carrier the blob refiner exists for.
	blob := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	res := scanJWT(t, `IMG = "data:image/png;base64,`+blob+`"`+"\n")
	for _, f := range res.Findings.Findings() {
		if strings.Contains(strings.ToLower(f.Message), "jwt") {
			t.Error("a base64 data URI was detected as a JWT")
		}
	}
}
