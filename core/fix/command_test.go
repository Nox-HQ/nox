package fix

import "testing"

func TestUpgradeCommand_ByEcosystem(t *testing.T) {
	t.Parallel()
	tests := []struct {
		eco, pkg, ver, want string
	}{
		{"go", "github.com/foo/bar", "1.2.4", "go get github.com/foo/bar@v1.2.4"},
		{"npm", "express", "4.19.0", "npm install express@4.19.0"},
		{"pypi", "requests", "2.32.0", "pip install 'requests>=2.32.0'"},
		// The finding and the plan each kept a copy of this table, and they
		// drifted: only the plan knew composer, only the finding maven.
		{"composer", "symfony/http-kernel", "6.4.1", "composer update symfony/http-kernel"},
		{"maven", "org.example:lib", "1.2.0", "upgrade org.example:lib to 1.2.0 in your build file"},
		{"unknown", "x", "1.0.0", ""},
	}
	for _, tt := range tests {
		got := UpgradeCommand(tt.eco, tt.pkg, tt.ver)
		if got != tt.want {
			t.Errorf("UpgradeCommand(%s, %s, %s) = %q, want %q", tt.eco, tt.pkg, tt.ver, got, tt.want)
		}
	}
}
