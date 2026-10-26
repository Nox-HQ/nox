package osvcheck

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/fix"
)

// advisory is the ranges OSV publishes for one axios advisory (trimmed from the
// real records): introduced/fixed pairs for the 0.x and 1.x lines.
type advisory struct {
	id     string
	ranges [][2]string
}

var axiosAdvisories = []advisory{
	{"GHSA-cph5-m8f7-6c5x", [][2]string{{"0", "0.21.2"}}},
	{"GHSA-wf5p-g6vw-rhxx", [][2]string{{"1.0.0", "1.6.0"}, {"0.8.1", "0.28.0"}}},
	{"GHSA-mmx7-hfxf-jppx", [][2]string{{"1.0.0", "1.18.0"}, {"0", "0.33.0"}}},
	// Introduced after 0.21.1: invisible to a scan of 0.21.1, live on 0.33.0.
	{"GHSA-9fr6-4gfg-395g", [][2]string{{"0.27.2", "0.34.0"}, {"1.0.0", "1.20.0"}}},
	{"GHSA-x97p-jq2g-jp4f", [][2]string{{"0.28.0", "0.34.0"}, {"1.15.1", "1.20.0"}}},
}

func cmp(a, b string) int {
	var x, y [3]int
	_, _ = fmt.Sscanf(a, "%d.%d.%d", &x[0], &x[1], &x[2])
	_, _ = fmt.Sscanf(b, "%d.%d.%d", &y[0], &y[1], &y[2])
	for i := range x {
		if x[i] != y[i] {
			return x[i] - y[i]
		}
	}
	return 0
}

func (a advisory) affects(v string) bool {
	for _, r := range a.ranges {
		if cmp(v, r[0]) >= 0 && cmp(v, r[1]) < 0 {
			return true
		}
	}
	return false
}

// fakeOSV is version-aware, unlike a table keyed by package name: which
// advisories apply depends on the queried version, which is the whole point.
func fakeOSV(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := strings.CutPrefix(r.URL.Path, "/v1/vulns/"); ok {
			for _, a := range axiosAdvisories {
				if a.id != id {
					continue
				}
				var affected []map[string]any
				for _, rg := range a.ranges {
					affected = append(affected, map[string]any{
						"package": map[string]string{"name": "axios", "ecosystem": "npm"},
						"ranges": []map[string]any{{"type": "SEMVER", "events": []map[string]string{
							{"introduced": rg[0]}, {"fixed": rg[1]}}}},
					})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"id": a.id, "summary": a.id, "affected": affected})
				return
			}
			http.NotFound(w, r)
			return
		}
		var req struct {
			Queries []struct {
				Version string `json:"version"`
			} `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		type res struct {
			Vulns []map[string]string `json:"vulns"`
		}
		var out struct {
			Results []res `json:"results"`
		}
		for _, q := range req.Queries {
			var rs res
			for _, a := range axiosAdvisories {
				if a.affects(q.Version) {
					rs.Vulns = append(rs.Vulns, map[string]string{"id": a.id})
				}
			}
			out.Results = append(out.Results, rs)
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
}

func axiosFindings() []findings.Finding {
	// What a scan of axios 0.21.1 reports: only the advisories that affect it.
	var out []findings.Finding
	for _, a := range axiosAdvisories {
		if !a.affects("0.21.1") {
			continue
		}
		fixed := a.ranges[len(a.ranges)-1][1]
		if a.id == "GHSA-wf5p-g6vw-rhxx" || a.id == "GHSA-mmx7-hfxf-jppx" {
			fixed = map[string]string{"GHSA-wf5p-g6vw-rhxx": "0.28.0", "GHSA-mmx7-hfxf-jppx": "0.33.0"}[a.id]
		}
		out = append(out, findings.Finding{
			RuleID:   "VULN-001",
			Location: findings.Location{FilePath: "package-lock.json"},
			Metadata: map[string]string{"ecosystem": "npm", "package": "axios", "version": "0.21.1", "fixed_in": fixed},
		})
	}
	return out
}

// The reported case: axios 0.21.1 plans to 0.33.0, which still has two
// advisories that 0.21.1 never had. The plan must reach 0.34.0 in one go.
func TestAxios0211PlansToTheVersionThatClearsEverything(t *testing.T) {
	srv := fakeOSV(t)
	defer srv.Close()

	before := fix.PlanUpgrades(axiosFindings(), fix.Options{})
	if len(before.Actions) != 1 || before.Actions[0].To != "0.33.0" {
		t.Fatalf("premise: without the checker the plan should pick 0.33.0, got %+v", before.Actions)
	}

	plan := fix.PlanUpgrades(axiosFindings(), fix.Options{Checker: New(srv.URL)})
	if len(plan.Actions) != 1 || plan.Actions[0].To != "0.34.0" {
		t.Fatalf("want 0.34.0, got actions=%+v held=%+v", plan.Actions, plan.Held)
	}
}

func TestUnreachableSourceIsUnverifiedNotClear(t *testing.T) {
	srv := fakeOSV(t)
	srv.Close() // closed address
	plan := fix.PlanUpgrades(axiosFindings(), fix.Options{Checker: New(srv.URL)})
	if len(plan.Actions) != 1 || !plan.Actions[0].Unverified {
		t.Fatalf("an unreachable source must mark the action unverified: %+v", plan.Actions)
	}
}
