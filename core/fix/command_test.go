package fix

import (
	"strings"
	"testing"
)

func TestUpgradeCommand_ByEcosystem(t *testing.T) {
	t.Parallel()
	tests := []struct {
		eco, pkg, ver, want string
	}{
		{"go", "github.com/foo/bar", "1.2.4", "go get github.com/foo/bar@v1.2.4"},
		{"npm", "express", "4.19.0", "npm install express@4.19.0"},
		{"pypi", "requests", "2.32.0", "pip install --upgrade --only-binary :all: requests==2.32.0"},
		// The finding and the plan each kept a copy of this table, and they
		// drifted: only the plan knew composer, only the finding maven.
		{"composer", "symfony/http-kernel", "6.4.1", "composer update symfony/http-kernel --with-dependencies --no-scripts --no-plugins"},
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

// The command a finding or plan shows is the one nox fix apply runs. They were
// two tables, and for three ecosystems the shown one was the unsafe form apply
// deliberately avoids: `bundle update` installs gems and compiles native
// extensions, `composer update` runs scripts and plugins, and `dotnet add
// package` restores, which runs MSBuild targets from the new package. A person
// copying the shown command ran code nox itself refuses to run.
func TestShownCommandIsTheOneApplyRuns(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ eco, want string }{
		{"go", "go get example.com/pkg@v1.2.3"},
		{"pypi", "pip install --upgrade --only-binary :all: pkg==1.2.3"},
		{"cargo", "cargo update -p pkg --precise 1.2.3"},
		{"rubygems", "bundle lock --update pkg --conservative"},
		{"composer", "composer update pkg --with-dependencies --no-scripts --no-plugins"},
		{"nuget", "dotnet add package pkg --version 1.2.3 --no-restore"},
	} {
		pkg := "pkg"
		if tc.eco == "go" {
			pkg = "example.com/pkg"
		}
		tool, args, ok := Invocation(tc.eco, pkg, "1.2.3")
		if !ok {
			t.Fatalf("%s: apply has no invocation", tc.eco)
		}
		applied := tool + " " + strings.Join(args, " ")
		if applied != tc.want {
			t.Errorf("%s: apply runs %q, want %q", tc.eco, applied, tc.want)
		}
		if shown := UpgradeCommand(tc.eco, pkg, "1.2.3"); shown != applied {
			t.Errorf("%s: shown %q, apply runs %q", tc.eco, shown, applied)
		}
	}
}
