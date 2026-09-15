package catalog

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The README's rule count is a claim, and a claim nothing checks rots.
//
// It said 1506 across five suites, 938 secrets and 500 IaC, while the catalog
// held 1485, 882 and 482. Nobody wrote a wrong number: every rule retirement
// since made the sentence a little less true, and a count is exactly the kind
// of statement that goes on reading as current long after it stopped being so.
//
// Gating it means the next retirement either updates the README or fails here.
func TestREADMERuleCountsMatchTheCatalog(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(body)

	cat := Catalog()
	perFamily := map[string]int{}
	for _, r := range cat {
		perFamily[strings.SplitN(r.ID, "-", 2)[0]]++
	}

	claims := []struct {
		pattern *regexp.Regexp
		want    int
		what    string
	}{
		{regexp.MustCompile(`Nox ships with \*\*(\d+) built-in rules\*\*`), len(cat), "the total"},
		{regexp.MustCompile(`### Secrets \((\d+) rules\)`), perFamily["SEC"], "the SEC family"},
		{regexp.MustCompile(`### AI Security \((\d+) rules\)`), perFamily["AI"], "the AI family"},
		{regexp.MustCompile(`### Infrastructure as Code \((\d+) rules\)`), perFamily["IAC"], "the IAC family"},
	}
	for _, c := range claims {
		m := c.pattern.FindStringSubmatch(readme)
		if m == nil {
			t.Errorf("README no longer states %s in the form %s expects — update the "+
				"pattern here rather than dropping the claim", c.what, c.pattern)
			continue
		}
		got, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("README says %d for %s; the catalog holds %d", got, c.what, c.want)
		}
	}
}
