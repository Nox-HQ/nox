package secrets

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/nox-hq/nox/core/findings"
)

// publishedValues are credentials their vendor prints in its own
// documentation, each with what it is. They authenticate nothing: AWS's
// example keys belong to no account, and Stripe's sample keys are documented
// as public. A project that copies the vendor's example into a README or an
// .env.example was told it had leaked a critical credential.
//
// The table holds exact values, each read from the vendor's documentation, and
// nothing derived from them: "contains EXAMPLE" would also describe a real key
// somebody named badly, and the placeholder refiner already owns that question.
//
// It is keyed by the SHA-256 of each value rather than the value. A vendor's
// sample key written into nox's source is what every secret scanner, GitHub's
// push protection and nox's own among them, reports as a key being committed,
// and a digest still matches only the whole value. Which values these are is
// pinned by TestPublishedValuesAreTheDocumentedOnes.
//
//	AWS    docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
//	       docs.aws.amazon.com/sdkref/latest/guide/file-format.html
//	Stripe docs.stripe.com/api ("A sample test API key is included in all the
//	       examples here") and docs.stripe.com/keys
var publishedValues = map[string]string{
	"1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3": "AWS's published example access key ID",           // AKIAIOSFODNN7EXAMPLE
	"c6ea27c534f993d31f0aef882e3d200e7b87470c379ae79c8f9b19d3bd363dc9": "AWS's published example access key ID",           // AKIAI44QH8DHBEXAMPLE
	"cb20d34a7adda2f5d2043836051e242fd4c2b233e02c80c91fe9d5af9b100574": "AWS's published example temporary access key ID", // ASIAIOSFODNN7EXAMPLE
	"7a259e311eb57eb32596c9467e5033dc9184a4a7f1578eeea68ec7834c54651f": "AWS's published example temporary access key ID", // ASIAI44QH8DHBEXAMPLE
	"78314b11be2e581549ac1c4f616563fad3fdf0c3b71678f6e2299182080e0598": "AWS's published example secret access key",       // wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
	"e21b597ba6b9cafa59d9ebc4d65c0385f5eb3fa56abab2607fa76589ad849a33": "AWS's published example secret access key",       // je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
	"f2d6ca16515033e5dce14eba840b979d27b5cbae24bb3e5bf484339667f86397": "Stripe's published sample test key",              // stripeAPIReferenceKey in the tests
	"2cafc0970149a84f3b9e62eaf169f36f59907a3b3e31f7b82e68c69cd27f7326": "Stripe's published sample test key",              // stripeQuickstartKey in the tests
}

// publishedValueOf says which vendor published value, if one did.
func publishedValueOf(value string) (string, bool) {
	sum := sha256.Sum256([]byte(value))
	what, ok := publishedValues[hex.EncodeToString(sum[:])]
	return what, ok
}

// classifyValue reclassifies a finding whose rule matched a credential's shape
// when the value itself says more than the shape does. The finding is kept: it
// changes what it claims and records that it did, with the severity the rule
// declares, so a reader never has to infer a reclassification from a rating.
//
// It runs after every refiner that can drop a finding and reads the value the
// finding claims, never the matched span: a span that binds a name to a real
// credential, on a line that also holds an example, is not an example.
func classifyValue(content []byte, f *findings.Finding) {
	value, offset := findingClaimedValue(content, f)
	if !standsAlone(content, offset, len(value)) {
		return
	}
	if what, ok := publishedValueOf(value); ok {
		reclassify(f, findings.SeverityInfo, findings.ValueClassPublishedExample,
			what+": public documentation, not a credential")
	}
}

func reclassify(f *findings.Finding, severity findings.Severity, class, message string) {
	if f.Metadata == nil {
		f.Metadata = map[string]string{}
	}
	f.Metadata[findings.MetaValueClass] = class
	f.Metadata[findings.MetaRuleSeverity] = string(f.Severity)
	f.Severity = severity
	f.Message = message
}

// standsAlone reports whether the value at content[start:start+n] is a whole
// token. A rule with a fixed-length pattern matches the first characters of a
// longer run, and a longer run that begins with a published example is a
// different value.
func standsAlone(content []byte, start, n int) bool {
	if start < 0 || n == 0 || start+n > len(content) {
		return false
	}
	if start > 0 && isAlnumByte(content[start-1]) {
		return false
	}
	if end := start + n; end < len(content) {
		if c := content[end]; isAlnumByte(c) || c == '/' || c == '+' {
			return false
		}
	}
	return true
}
