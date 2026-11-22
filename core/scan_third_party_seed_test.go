package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsSeedDataPath(t *testing.T) {
	for _, c := range []struct {
		path string
		want bool
	}{
		{"prisma/seed.ts", true},
		{"backend/app/seed.py", true},
		{"src/seeds/users.js", true},
		{"crm/core/management/commands/seed_data.py", true},
		{"src/main/java/com/acme/seed/DemoDataSeeder.java", true},
		{"src/main/java/com/acme/service/SeedService.java", true},
		{"src/main/resources/db/migration/V2__seed.sql", true},
		{"db/migrations/0003_add_users.py", true},
		{"scripts/db_seed.py", true},
		{"src/routes/users.ts", false},
		{"src/lib/seedling.ts", false},
		{"src/crypto/seedRandom.ts", false},
		{"app/models/proceed.py", false},
	} {
		if got := IsSeedDataPath(c.path); got != c.want {
			t.Errorf("IsSeedDataPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// A committed dependency tree is the dependency's code: the code-pattern
// rules are dropped there and a secret is kept. Seed data's e-mail addresses
// are made-up demo users: DATA-001 is dropped there and a secret is kept.
// The same lines in the project's own source are reported.
func TestScan_ThirdPartyTreesAndSeedData(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	jwtDecode := "const jwt = require('jsonwebtoken');\nmodule.exports = (t) => jwt.decode(t);\n"
	awsKey := "const k = \"AKIAIOSFODNN7EXAMPL2\";\n"
	write("node_modules/lib/index.js", jwtDecode+awsKey)
	write("src/auth.js", jwtDecode)
	write("prisma/seed.ts", "const users = [{ email: 'dana.whitfield@northwind-clinic.com' }];\n"+awsKey)
	write("src/contact.ts", "export const owner = 'dana.whitfield@northwind-clinic.com';\n")

	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]bool{}
	for _, f := range res.Findings.Findings() {
		if got[f.Location.FilePath] == nil {
			got[f.Location.FilePath] = map[string]bool{}
		}
		got[f.Location.FilePath][f.RuleID] = true
	}
	hasSecret := func(path string) bool {
		for id := range got[path] {
			if len(id) > 4 && id[:4] == "SEC-" {
				return true
			}
		}
		return false
	}
	if got["node_modules/lib/index.js"]["APPCFG-003"] {
		t.Error("APPCFG-003 reported inside node_modules: a dependency's code")
	}
	if !got["src/auth.js"]["APPCFG-003"] {
		t.Error("APPCFG-003 not reported in src/auth.js: the drop must be scoped to third-party trees")
	}
	if !hasSecret("node_modules/lib/index.js") {
		t.Errorf("no SEC-* finding inside node_modules: a secret is kept wherever it sits (got %v)", got["node_modules/lib/index.js"])
	}
	if got["prisma/seed.ts"]["DATA-001"] {
		t.Error("DATA-001 reported in prisma/seed.ts: a seed file's addresses are demo users")
	}
	if !got["src/contact.ts"]["DATA-001"] {
		t.Error("DATA-001 not reported in src/contact.ts: the drop must be scoped to seed data")
	}
	if !hasSecret("prisma/seed.ts") {
		t.Errorf("no SEC-* finding in prisma/seed.ts: a secret in seed data is kept (got %v)", got["prisma/seed.ts"])
	}
}
