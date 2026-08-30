package findings

import "testing"

// TestAddressesIsTheOneSelector guards the cross-adapter duplication this
// codebase has fixed five times.
//
// Every surface that lets a person name a finding — the CLI, the MCP server,
// the LSP — accepts a fingerprint prefix, because a full SHA-256 is 64
// characters and nobody retypes one. Each grew its own copy, and they had
// already drifted: the MCP server compared case-sensitively and the CLI
// lowercased the input, so the same prefix resolved on one surface and not the
// other. A person cannot debug that; it looks like the finding is gone.
func TestAddressesIsTheOneSelector(t *testing.T) {
	f := Finding{
		RuleID:            "SEC-003",
		Fingerprint:       "65f66b3f2c177f2795e5db6ebff43f41",
		RetiredRuleIDs:    []string{"SEC-903"},
		AliasFingerprints: []string{"deadbeefdeadbeef"},
	}

	for _, sel := range []string{
		"SEC-003", "sec-003", // current rule ID, either case
		"SEC-903",                          // a retired ID a waiver may still name
		"65f66b3f2c177f2795e5db6ebff43f41", // the whole fingerprint
		"65f66b3f", "65F66B3F",             // a prefix, either case
		"deadbeef", // the fingerprint a retired rule would have produced
	} {
		if !f.Addresses(sel) {
			t.Errorf("Addresses(%q) = false; a selector a person would reasonably "+
				"type does not resolve", sel)
		}
	}

	for _, sel := range []string{
		"", "   ", // an omitted argument must not select everything
		"SEC-004", "ffffffff", "65f66b3f2c177f2795e5db6ebff43f41x",
	} {
		if f.Addresses(sel) {
			t.Errorf("Addresses(%q) = true; it names a different finding, or nothing", sel)
		}
	}

	// A finding with no fingerprint cannot be addressed by one, and must not
	// match every prefix by accident.
	blank := Finding{RuleID: "SEC-003"}
	if blank.MatchesFingerprint("65f66b3f") {
		t.Error("a finding with no fingerprint matched a fingerprint prefix")
	}
}
