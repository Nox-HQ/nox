package iac

import "testing"

// IAC-124 asks that an image say who maintains it. The OCI image spec's key for
// that is org.opencontainers.image.authors; `maintainer` is the older Docker
// convention. Either satisfies the rule, wherever it sits in a LABEL
// instruction: after another key, quoted, or on a continuation line (#1009).
func TestIAC124AcceptsEitherAuthorsKeyAnywhereInALabel(t *testing.T) {
	cases := []struct {
		name  string
		file  string
		fires bool
	}{
		{"no label", "FROM alpine:3.20\nUSER nobody\n", true},
		{"unrelated label", "FROM alpine:3.20\nLABEL org.opencontainers.image.source=https://example.com/x\n", true},
		{"key only in a comment", "FROM alpine:3.20\n# org.opencontainers.image.authors=team@example.com\n", true},
		{"key in a RUN argument", "FROM alpine:3.20\nRUN echo maintainer=x\n", true},
		{"key as a value", "FROM alpine:3.20\nLABEL description=\"ask the maintainer\"\n", true},
		{"key as a value after =", "FROM alpine:3.20\nLABEL description=maintainer=x\n", true},
		{"maintainer first", "FROM alpine:3.20\nLABEL maintainer=\"team@example.com\"\n", false},
		{"oci authors", "FROM alpine:3.20\nLABEL org.opencontainers.image.authors=\"Platform team\"\n", false},
		{"after another key", "FROM alpine:3.20\nLABEL org.opencontainers.image.source=x org.opencontainers.image.authors=y\n", false},
		{"quoted key", "FROM alpine:3.20\nLABEL \"org.opencontainers.image.authors\"=\"y\"\n", false},
		{"continuation line", "FROM alpine:3.20\nLABEL org.opencontainers.image.source=x \\\n      org.opencontainers.image.authors=y\n", false},
		{"lower-case instruction", "FROM alpine:3.20\nlabel maintainer=y\n", false},
	}
	a := NewAnalyzer()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := a.ScanFile("Dockerfile", []byte(tc.file))
			if err != nil {
				t.Fatal(err)
			}
			if hasRule(got, "IAC-124") != tc.fires {
				t.Errorf("IAC-124 fired = %v, want %v", !tc.fires, tc.fires)
			}
		})
	}
}
