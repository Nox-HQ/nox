package rules

import "testing"

// stripLineComments must remove `#` comments so a keyword mentioned only in a
// comment cannot satisfy an absence rule's required property — but it must
// never cut real content, because for an absence rule that would turn a
// present property into an absent one and fire a false positive. The guard is
// deliberately conservative: a `#` is a comment only at line start or when
// preceded by whitespace with no quote earlier on the line.
func TestStripLineComments(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "full-line comment removed",
			in:   "FROM alpine\n# no HEALTHCHECK here\nUSER x\n",
			want: "FROM alpine\n\nUSER x\n",
		},
		{
			name: "trailing comment with no prior quote removed",
			in:   "uses: actions/upload-artifact@sha # attested elsewhere\n",
			want: "uses: actions/upload-artifact@sha\n",
		},
		{
			name: "hash inside a double-quoted value is kept",
			in:   `name: "release # attested"` + "\n",
			want: `name: "release # attested"` + "\n",
		},
		{
			name: "hash inside a single-quoted value is kept",
			in:   "tag: 'v1 # attest'\n",
			want: "tag: 'v1 # attest'\n",
		},
		{
			name: "url fragment inside quotes is kept",
			in:   `url: "https://x/a#attest"` + "\n",
			want: `url: "https://x/a#attest"` + "\n",
		},
		{
			name: "hash not preceded by whitespace is not a comment",
			in:   "value: abc#attest\n",
			want: "value: abc#attest\n",
		},
		{
			name: "comment after an unquoted value removed",
			in:   "attestations: read # keep this key, drop the note\n",
			want: "attestations: read\n",
		},
		{
			name: "JSON is unaffected (all # are inside quotes)",
			in:   `{"note": "requires # attestation"}` + "\n",
			want: `{"note": "requires # attestation"}` + "\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(stripLineComments([]byte(tc.in)))
			if got != tc.want {
				t.Errorf("stripLineComments(%q)\n  = %q\n want %q", tc.in, got, tc.want)
			}
		})
	}
}
