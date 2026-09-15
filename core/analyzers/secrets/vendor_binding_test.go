package secrets

import (
	"slices"
	"testing"
)

// Nine vendor rules matched a bare token whose only tie to the vendor was the
// vendor's NAME appearing somewhere nearby. For vendors with a distinctive
// credential format the answer is the format (SEC-661 PostHog, SEC-446
// Cloudflare). For these nine there is no published distinctive format, so the
// evidence has to be the binding: the vendor's own key name, an assignment, and
// then a value of the right shape.
//
// That is the shape SEC-053, SEC-158 and SEC-159 already use for Fastly,
// Segment and Amplitude; these now match it.
//
// One correction recorded here because it is the same error the workstream is
// about: SEC-540 is NAMECHEAP, and a first pass bound it to `heap` because
// "namecheap" contains that substring. The vendor of a rule is its description,
// not a substring of its keyword.

func TestVendorRulesRequireABinding(t *testing.T) {
	bound := []struct{ rule, line string }{
		{"SEC-665", `fullstory_api_key = "aB3cD4eF5gH6iJ7kL8mN"`},
		{"SEC-652", `jenkins_api_token = "aB3cD4eF5gH6iJ7kL8mN"`},
		{"SEC-659", `split_api_key = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV"`},
		{"SEC-635", `salesforce_api_key = "ab3cd4ef5gh6ij7kl8mn9op0qr1st2uv"`},
		{"SEC-664", `heap_api_key = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV"`},
		{"SEC-540", `namecheap_api_key = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV"`},
		{"SEC-629", `lob_api_key = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV"`},
		{"SEC-590", `wave_api_key = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV"`},
		{"SEC-616", `fcm_server_key = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV"`},
	}
	for _, tc := range bound {
		got := idsFor(t, "config.py", "# vendor config\n"+tc.line+"\n")
		if !slices.Contains(got, tc.rule) {
			t.Errorf("%s does not report its own bound credential: %s\n   ids=%v",
				tc.rule, tc.line, got)
		}
	}
}

// TestVendorRulesIgnoreABareTokenNearTheName is the 2,349-finding class this
// family produced: a token that merely sits near the vendor's name.
func TestVendorRulesIgnoreABareTokenNearTheName(t *testing.T) {
	for _, tc := range []struct{ rule, body string }{
		{"SEC-616", "server: fcm\nrequest_id = \"aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV\"\n"},
		{"SEC-664", "# heap analytics\nsession = \"aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV\"\n"},
		{"SEC-659", "# split testing\ndigest = \"aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV\"\n"},
		{"SEC-590", "# wave docs\nchecksum = \"aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV\"\n"},
		{"SEC-629", "# lob mailing\ntrace = \"aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV\"\n"},
	} {
		if got := idsFor(t, "notes.md", tc.body); slices.Contains(got, tc.rule) {
			t.Errorf("%s still fires on a token that merely sits near the vendor name:\n%s",
				tc.rule, tc.body)
		}
	}
}

// TestSEC540IsNamecheapNotHeap pins the correction.
func TestSEC540IsNamecheapNotHeap(t *testing.T) {
	got := idsFor(t, "c.py", `namecheap_api_key = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV"`+"\n")
	if !slices.Contains(got, "SEC-540") {
		t.Errorf("SEC-540 does not report a Namecheap key; ids=%v", got)
	}
	// And Heap's own rule must not claim Namecheap's credential.
	if slices.Contains(got, "SEC-664") {
		t.Error("SEC-664 (Heap) reports a Namecheap key — `namecheap` contains `heap`, " +
			"and that substring is exactly what this workstream is about")
	}
}
