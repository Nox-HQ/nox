package secrets

import "testing"

// TestURLCredentialRules_TemplatedPasswordIsNotALeak: a placeholder in the
// password slot of a connection string is configuration, not a credential.
// A literal password still fires.
func TestURLCredentialRules_TemplatedPasswordIsNotALeak(t *testing.T) {
	quiet := []string{
		`DATABASE_URL=postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@db:5432/app`,
		`url = "git+https://${GIT_USERNAME}:${GIT_PASSWORD}@github.com/org/repo.git"`,
		`redis://default:$REDIS_PASSWORD@cache:6379/0`,
		`mongodb+srv://app:{{ .Values.mongo.password }}@cluster0.example.net/db`,
		`export DSN="mysql://root:%s@127.0.0.1:3306/test"`,
		`conn = "postgresql://user:<password>@localhost/db"`,
		`'git': 'https://${AUTH_USER}:****@github.com/user/myproject.git'`,
	}
	loud := map[string]string{
		`DATABASE_URL=postgres://app:s3cr3t-Pa55@db:5432/app`:              "SEC-073",
		`url = "https://deploy:ghp_realtokenvalue1234@github.com/o/r.git"`: "SEC-085",
		`redis://default:hunter2hunter2@cache:6379/0`:                      "SEC-076",
		`mongodb+srv://app:Qx9!pLm2@cluster0.example.net/db`:               "SEC-074",
	}
	a := NewAnalyzer()
	scan := func(line string) map[string]bool {
		found, err := a.ScanFile("config.env", []byte(line+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		ids := map[string]bool{}
		for _, f := range found {
			ids[f.RuleID] = true
		}
		return ids
	}
	for _, line := range quiet {
		ids := scan(line)
		for _, id := range []string{"SEC-073", "SEC-074", "SEC-076", "SEC-085"} {
			if ids[id] {
				t.Errorf("%s fired on a templated password: %s", id, line)
			}
		}
	}
	for line, id := range loud {
		if !scan(line)[id] {
			t.Errorf("%s did not fire on a literal password: %s", id, line)
		}
	}
	if !scan(`"https://u:p@h/x"`)["SEC-085"] {
		// A one-character password is still a literal; this documents that
		// the validator judges shape, not strength.
		t.Errorf("SEC-085 should still fire on a literal one-character password")
	}
}
