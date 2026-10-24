package authz

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/reasoning"
)

const expectMarker = "expect: AUTHZ-001"

// scanRoot runs the analyzer, enabled, over one fixture app.
func scanRoot(t *testing.T, root string, enable bool) []findings.Finding {
	t.Helper()
	arts, err := discovery.NewWalker(root).Walk()
	if err != nil {
		t.Fatal(err)
	}
	a := NewAnalyzer()
	if enable {
		a.EnableOptIn([]string{RuleID})
	}
	fs, err := a.ScanArtifacts(context.Background(), arts)
	if err != nil {
		t.Fatal(err)
	}
	return fs.Findings()
}

// expectedLines returns every file:line carrying the expect marker.
func expectedLines(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		rel, _ := filepath.Rel(root, p)
		sc := bufio.NewScanner(f)
		for n := 1; sc.Scan(); n++ {
			if strings.Contains(sc.Text(), expectMarker) {
				out = append(out, fmt.Sprintf("%s:%d", filepath.ToSlash(rel), n))
			}
		}
		return sc.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func gotLines(fs []findings.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, fmt.Sprintf("%s:%d", f.Location.FilePath, f.Location.StartLine))
	}
	sort.Strings(out)
	return out
}

func caseDirs(t *testing.T, group string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("testdata", group))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, filepath.Join("testdata", group, e.Name()))
		}
	}
	if len(out) == 0 {
		t.Fatalf("no %s fixtures", group)
	}
	return out
}

// Every vulnerable fixture is reported, at exactly the lookup the marker
// names and nowhere else.
func TestVulnerableFixturesReportAtTheLookup(t *testing.T) {
	for _, dir := range caseDirs(t, "vulnerable") {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			want := expectedLines(t, dir)
			if len(want) == 0 {
				t.Fatal("vulnerable fixture carries no expect marker")
			}
			if got := gotLines(scanRoot(t, dir, true)); !reflect.DeepEqual(got, want) {
				t.Errorf("findings = %v, want %v", got, want)
			}
		})
	}
}

// Every safe fixture is one counterexample class of the proposition, and none
// is reported.
func TestSafeFixturesAreCounterexamples(t *testing.T) {
	for _, dir := range caseDirs(t, "safe") {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			if want := expectedLines(t, dir); len(want) != 0 {
				t.Fatalf("safe fixture carries an expect marker: %v", want)
			}
			if got := scanRoot(t, dir, true); len(got) != 0 {
				t.Errorf("counterexample reported: %s", got[0].Message)
			}
		})
	}
}

// AUTHZ-001 is opt-in: silent unless scan.rules.enable names it, and its rule
// says so in the catalogue.
func TestOptInByDefault(t *testing.T) {
	dir := filepath.Join("testdata", "vulnerable", "inline_sql_route_auth")
	if got := scanRoot(t, dir, false); len(got) != 0 {
		t.Fatalf("reported without being enabled: %v", gotLines(got))
	}
	rs := NewAnalyzer().Rules().Rules()
	if len(rs) != 1 || rs[0].ID != RuleID || !rs[0].OptIn {
		t.Fatalf("rule catalogue = %+v, want one opt-in %s", rs, RuleID)
	}
}

// The finding carries what a reviewer needs to verify it: the route, the
// authentication it saw, the lookup, and where the identifier came from.
func TestFindingNamesRouteAuthAndLookup(t *testing.T) {
	fs := scanRoot(t, filepath.Join("testdata", "vulnerable", "inline_sql_route_auth"), true)
	if len(fs) != 1 {
		t.Fatalf("got %d findings", len(fs))
	}
	f := fs[0]
	want := map[string]string{
		"route":      "GET /:id",
		"route_file": "src/routes/invoices.js",
		"auth":       "requireAuth",
		"sink":       "query",
		"model":      "invoice",
		"id_source":  "path",
		"cwe":        "CWE-639",
	}
	for k, v := range want {
		if f.Metadata[k] != v {
			t.Errorf("metadata[%s] = %q, want %q", k, f.Metadata[k], v)
		}
	}
	if f.Severity != findings.SeverityMedium || f.Confidence != findings.ConfidenceLow {
		t.Errorf("severity/confidence = %s/%s, want medium/low", f.Severity, f.Confidence)
	}
}

// A cleared candidate is not dropped silently: each counterexample files a
// refutation for the lookup it cleared, with its reason, so stage accounting
// can count AUTHZ candidates against what refuted them. A route that never
// met the antecedent (no authentication) is no candidate and files nothing.
func TestCounterexamplesAreRecordedAsRefutations(t *testing.T) {
	for _, dir := range caseDirs(t, "safe") {
		name := filepath.Base(dir)
		t.Run(name, func(t *testing.T) {
			arts, err := discovery.NewWalker(dir).Walk()
			if err != nil {
				t.Fatal(err)
			}
			store := reasoning.New()
			a := NewAnalyzer()
			a.EnableOptIn([]string{RuleID})
			a.RecordReasoningTo(store)
			if _, err := a.ScanArtifacts(context.Background(), arts); err != nil {
				t.Fatal(err)
			}
			notCandidates := map[string]bool{
				"public_route_no_auth":            true,
				"optional_auth_and_session_hooks": true,
				"slug_not_identifier":             true,
				"security_headers_are_not_auth":   true,
				"text_in_strings_and_comments":    true,
			}
			subjects := store.Subjects()
			if notCandidates[name] {
				if len(subjects) != 0 {
					t.Errorf("a non-candidate filed %d refutations", len(subjects))
				}
				return
			}
			if len(subjects) != 1 {
				t.Fatalf("filed %d refutations, want 1", len(subjects))
			}
			l := store.About(subjects[0])
			if !strings.HasPrefix(subjects[0].ID, RuleID+"@") || len(l.Claims) != 1 || l.Claims[0].Statement == "" {
				t.Errorf("refutation = %+v on %s", l.Claims, subjects[0].ID)
			}
		})
	}
}

// The finding names where the identifier came from, separately from the
// lookup call: a path parameter read through db.query() is a path id, not a
// "query" one.
func TestFindingNamesTheIdentifierSource(t *testing.T) {
	cases := []struct{ fixture, source, phrase, sink string }{
		{"inline_sql_route_auth", "path", "supplies in the route path, via query()", "query"},
		{"query_id_lookup", "query", "supplies in the query string, via findById()", "findById"},
		{"body_id_update", "body", "supplies in the request body, via findByIdAndUpdate()", "findByIdAndUpdate"},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			fs := scanRoot(t, filepath.Join("testdata", "vulnerable", c.fixture), true)
			if len(fs) != 1 {
				t.Fatalf("got %d findings", len(fs))
			}
			f := fs[0]
			if f.Metadata["id_source"] != c.source || f.Metadata["sink"] != c.sink {
				t.Errorf("id_source/sink = %q/%q, want %q/%q", f.Metadata["id_source"], f.Metadata["sink"], c.source, c.sink)
			}
			if !strings.Contains(f.Message, c.phrase) {
				t.Errorf("message %q does not contain %q", f.Message, c.phrase)
			}
		})
	}
}

// Not enabled (the default), every route the rule would report is a lead at
// the same lookup, and nothing is a finding; enabled, every one is a finding
// and none is a lead. A route is never both.
func TestDefaultModeHoldsLeadsNotFindings(t *testing.T) {
	for _, dir := range caseDirs(t, "vulnerable") {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			want := expectedLines(t, dir)
			arts, err := discovery.NewWalker(dir).Walk()
			if err != nil {
				t.Fatal(err)
			}
			a := NewAnalyzer()
			fs, err := a.ScanArtifacts(context.Background(), arts)
			if err != nil {
				t.Fatal(err)
			}
			if len(fs.Findings()) != 0 {
				t.Fatalf("default mode reported %d findings", len(fs.Findings()))
			}
			var got []string
			for _, l := range a.Leads() {
				got = append(got, fmt.Sprintf("%s:%d", l.FilePath, l.Line))
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("leads = %v, want %v", got, want)
			}
			if a.RoutesRead() == 0 {
				t.Error("no routes read")
			}

			on := NewAnalyzer()
			on.EnableOptIn([]string{RuleID})
			if _, err := on.ScanArtifacts(context.Background(), arts); err != nil {
				t.Fatal(err)
			}
			if len(on.Leads()) != 0 {
				t.Errorf("enabled rule also held leads: %+v", on.Leads())
			}
		})
	}
	for _, dir := range caseDirs(t, "safe") {
		arts, err := discovery.NewWalker(dir).Walk()
		if err != nil {
			t.Fatal(err)
		}
		a := NewAnalyzer()
		if _, err := a.ScanArtifacts(context.Background(), arts); err != nil {
			t.Fatal(err)
		}
		if len(a.Leads()) != 0 {
			t.Errorf("%s: counterexample held as a lead: %+v", filepath.Base(dir), a.Leads())
		}
	}
}

// A lead names the route as it is served: a router mounted at a prefix in
// another file carries that prefix.
func TestLeadRouteIncludesTheMountPrefix(t *testing.T) {
	arts, err := discovery.NewWalker(filepath.Join("testdata", "vulnerable", "mount_auth_other_file")).Walk()
	if err != nil {
		t.Fatal(err)
	}
	a := NewAnalyzer()
	if _, err := a.ScanArtifacts(context.Background(), arts); err != nil {
		t.Fatal(err)
	}
	if len(a.Leads()) != 1 || a.Leads()[0].Method != "DELETE" || a.Leads()[0].Path != "/api/notes/:noteId" || a.Leads()[0].IDSource != "path" {
		t.Fatalf("leads = %+v, want DELETE /api/notes/:noteId from the path", a.Leads())
	}
	for _, c := range []struct{ prefix, path, want string }{
		{"", "/:id", "/:id"},
		{"/api/invoices", "/:id", "/api/invoices/:id"},
		{"/api/invoices/", "/", "/api/invoices"},
		{"/api", "/v1/:id", "/api/v1/:id"},
	} {
		if got := joinRoutePath(c.prefix, c.path); got != c.want {
			t.Errorf("joinRoutePath(%q, %q) = %q, want %q", c.prefix, c.path, got, c.want)
		}
	}
}

// Two scans of the same tree produce the same findings in the same order.
func TestDeterministic(t *testing.T) {
	for _, dir := range caseDirs(t, "vulnerable") {
		a := scanRoot(t, dir, true)
		b := scanRoot(t, dir, true)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("%s: scans differ", dir)
		}
	}
}

// Falsify the counterexamples: each safe fixture must be reported once its
// one guard is removed. A safe fixture that stays silent without its guard
// guards nothing, and would let a regression pass.
func TestSafeFixturesFailWithoutTheirGuard(t *testing.T) {
	cases := []struct{ name, file, guard, without string }{
		{"scoped_sql", "routes.js", "WHERE id = $1 AND owner_id = $2', [req.params.id, req.user.sub]", "WHERE id = $1', [req.params.id]"},
		{"scoped_orm_where", "routes.js", ", userId: req.user.id", ""},
		{"compare_after_load", "routes.js", "!order || order.user.toString() !== req.user._id.toString()", "!order"},
		{"equals_method_check", "routes.js", "!post.author.equals(req.user._id)", "!post"},
		{"policy_call_casl", "routes.js", "ForbiddenError.from(req.ability).throwUnlessCan('read', project);", ""},
		{"authorize_helper", "routes.js", "await authorize(req.user, 'report:read', report);", ""},
		{"role_middleware", "routes.js", " requireRole('admin'),", ""},
		{"permission_argument", "routes.js", "auth('getUsers')", "auth()"},
		{"loader_middleware", "routes.js", " loadInvoiceForUser,", ""},
		{"router_param_loader", "routes.js", "router.param('postId', postByID);", ""},
		{"request_scoped_client", "routes.js", "req.db.ticket", "db.ticket"},
		{"scoped_repository_from_request", "routes.js", "repositoryFor(req)", "repositoryFor()"},
		{"middleware_context_to_service", "routes.js", "{ accountability: req.accountability }", "{}"},
		{"service_receives_principal", "routes.js", ", req.user.id)", ")"},
		{"owner_field_in_lookup", "routes.js", ", UserId: req.body.UserId", ""},
		{"forbidden_response", "routes.js", "if (!canView(doc, res.locals.viewer)) return res.status(403).end();", ""},
		{"role_read_in_handler", "routes.js", "req.user.role !== 'support' && String(ticket.requester) !== req.user.id", "!ticket"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := filepath.Join("testdata", "safe", c.name, c.file)
			b, err := os.ReadFile(src)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), c.guard) {
				t.Fatalf("guard %q not in fixture", c.guard)
			}
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, c.file), []byte(strings.Replace(string(b), c.guard, c.without, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := scanRoot(t, dir, true); len(got) != 1 {
				t.Errorf("without its guard the fixture reports %d findings, want 1", len(got))
			}
		})
	}
}
