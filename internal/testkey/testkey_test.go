package testkey

import (
	"regexp"
	"strings"
	"testing"
)

func TestValuesHaveTheShapeAndAreStable(t *testing.T) {
	tests := []struct {
		name  string
		make  func() string
		shape string
	}{
		{"access key ID", AWSAccessKeyID, `^AKIA[A-Z2-7]{16}$`},
		{"secret access key", AWSSecretAccessKey, `^[A-Za-z0-9/+]{40}$`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.make()
			if !regexp.MustCompile(tc.shape).MatchString(got) {
				t.Errorf("value does not match %s", tc.shape)
			}
			if again := tc.make(); again != got {
				t.Error("two calls returned different values; a fixture must be the same on every run")
			}
			// A published example is what these stand in for, so they must
			// not look like one.
			if strings.Contains(strings.ToUpper(got), "EXAMPLE") {
				t.Error("value contains EXAMPLE")
			}
		})
	}
}
