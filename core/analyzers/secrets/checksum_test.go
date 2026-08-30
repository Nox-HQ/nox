package secrets

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestChecksumAgainstPublishedTokens is the test that licenses everything else
// in checksum.go.
//
// The algorithm was not inferred. These are two independently published,
// expired GitHub tokens, and the implementation is checked against both. That
// matters more than it looks: an implementation verified against a token it
// GENERATED would prove only that its encoder and decoder agree, which is
// circular and would pass just as happily with the wrong CRC variant.
//
// Two independent tokens agreeing on a 6-character base62 checksum by chance
// is about one in 10^21. Castagnoli is checked too, and fails both, because
// "IEEE works" is a much weaker statement than "IEEE works and the obvious
// alternative does not".
//
// The stakes are why. A subtly wrong checksum records FALSE DETERMINISTIC
// claims — telling the ledger nox established something it got wrong, at a
// strength nothing else in this pipeline can reach. That is worse than the
// silence it replaces.
func TestChecksumAgainstPublishedTokens(t *testing.T) {
	// Expired sample tokens published in therootcompany/base62-token.js#2.
	for _, tok := range []string{
		"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",
		"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",
	} {
		consistent, applicable := verifyGitHubToken(tok)
		if !applicable {
			t.Errorf("%s: the check did not apply to a well-formed GitHub token", tok)
			continue
		}
		if !consistent {
			t.Errorf("%s: checksum did not verify. The algorithm is wrong, and every "+
				"deterministic claim built on it would be false.", tok)
		}
	}
}

// TestChecksumRejectsATamperedToken. One character changed in the body must
// break the checksum, or the check establishes nothing.
func TestChecksumRejectsATamperedToken(t *testing.T) {
	const valid = "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"
	tampered := "ghp_aQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq17"

	if consistent, applicable := verifyGitHubToken(tampered); !applicable {
		t.Fatal("the check did not apply to a tampered token of the right shape")
	} else if consistent {
		t.Error("a token with a changed body still verified; the checksum is not " +
			"actually being computed over the body")
	}
	if consistent, _ := verifyGitHubToken(valid); !consistent {
		t.Error("the untampered control failed, so the negative above proves nothing")
	}
}

// TestInapplicableValuesProduceNoVerdict is the distinction the whole
// capability model exists to protect, applied here.
//
// "I cannot check this" and "I checked this and it failed" are different
// statements and only the second is evidence. A function returning one bool
// would collapse them, and every value nox cannot check would silently become
// a refutation.
func TestInapplicableValuesProduceNoVerdict(t *testing.T) {
	for _, v := range []string{
		"",
		"not-a-token",
		"AKIAIOSFODNN7EXAMPLE", // a different provider entirely
		"ghp_tooshort",         // right prefix, wrong length
		"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XX", // right prefix, too long
		"ghp_zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq1!",   // non-base62 character
		"xoxb-1234567890-1234567890123-AbCdEfGhIjKl", // Slack: no checksum to verify
	} {
		if consistent, applicable := verifyGitHubToken(v); applicable {
			t.Errorf("the check claimed to apply to %q (consistent=%v); a value it "+
				"cannot speak about must produce no claim in either direction",
				v, consistent)
		}
	}
}

// TestQuotedValuesAreHandled. Matched values arrive with their quotes attached
// often enough that stripping them is not optional.
func TestQuotedValuesAreHandled(t *testing.T) {
	for _, v := range []string{
		`"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"`,
		`'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'`,
	} {
		consistent, applicable := verifyGitHubToken(v)
		if !applicable || !consistent {
			t.Errorf("%s: applicable=%v consistent=%v, want both true", v, applicable, consistent)
		}
	}
}

// TestBase62PadsAndRoundTrips guards the encoding independently of CRC, since a
// padding bug would corrupt exactly the low-checksum values that are hardest to
// notice by eye.
func TestBase62PadsAndRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		n    uint32
		want string
	}{
		{0, "000000"},
		{1, "000001"},
		{61, "00000z"},
		{62, "000010"},
	} {
		if got := encodeBase62(tc.n, 6); got != tc.want {
			t.Errorf("encodeBase62(%d, 6) = %q, want %q", tc.n, got, tc.want)
		}
	}
	if got := len(encodeBase62(0, 6)); got != 6 {
		t.Errorf("a zero checksum encoded to %d characters, want 6", got)
	}
}

// TestCorpusTokensCarryValidChecksums pins that the ground-truth samples remain
// values a correct scanner cannot deterministically refute.
//
// Both corpora had tokens with random bodies until checksum verification
// landed, which made them refutable — a poor true positive for "a hardcoded
// GitHub token", and in the refutation suite a case that guarded nothing.
//
// # Why this walks the corpus instead of listing tokens
//
// It used to check a hardcoded list of two literals copied out of the corpora,
// and it passed while a third sample drifted: testdata/precision-suite/
// tp_secrets.go carried a random body, so nox recorded a KindStatic refutation
// saying "this is not a GitHub credential" against a sample the corpus declares
// a true positive, and reported it anyway. Nothing failed, because the test was
// not looking at the corpus — it was looking at a copy of the part of the
// corpus somebody remembered to copy.
//
// That is the same defect shape as the unreachable policy validation found in
// Track D5: a check written correctly against the wrong input. A test that
// pins a transcription of the thing it guards cannot detect the thing it
// guards changing. It was found by Track C3, which went looking for subjects
// whose evidence contradicts itself and found exactly one.
func TestCorpusTokensCarryValidChecksums(t *testing.T) {
	roots := []string{
		filepath.Join("..", "..", "..", "testdata", "precision-suite"),
		filepath.Join("..", "..", "..", "testdata", "refutation-suite"),
		filepath.Join("..", "..", "..", "testdata", "reachability-suite"),
	}
	tokenPattern := regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36}`)

	var checked int
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, tok := range tokenPattern.FindAllString(string(content), -1) {
				checked++
				consistent, applicable := verifyGitHubToken(tok)
				if !applicable {
					t.Errorf("%s: %s is not a checkable GitHub token", path, tok)
					continue
				}
				if !consistent {
					t.Errorf("%s: %s carries an invalid checksum. A checksum-aware scanner "+
						"deterministically refutes it, so the corpus declares a sample whose "+
						"strongest evidence contradicts what the corpus says it is", path, tok)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}

	// A pattern that stops matching would make every assertion above vacuous,
	// and it would look exactly like a clean corpus.
	if checked == 0 {
		t.Fatal("no GitHub token was found in any corpus; this test is checking nothing")
	}
	t.Logf("checked %d GitHub tokens across the committed corpora", checked)
}
