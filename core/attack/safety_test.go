package attack

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nox-hq/nox-core/evidence"
)

func TestParseProfile(t *testing.T) {
	tests := []struct {
		in      string
		want    Profile
		wantErr bool
	}{
		{"safe", ProfileSafe, false},
		{"sandbox", ProfileSandbox, false},
		{"staging", ProfileStaging, false},
		{"authorized-live", ProfileAuthorizedLive, false},
		{"SAFE", "", true},
		{"", "", true},
		{"live", "", true},
	}
	for _, tc := range tests {
		got, err := ParseProfile(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseProfile(%q) err=%v wantErr=%v", tc.in, err, tc.wantErr)
		}
		if err == nil && got != tc.want {
			t.Errorf("ParseProfile(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestProfileNetworkAndAuthorization(t *testing.T) {
	tests := []struct {
		p        Profile
		wantNet  bool
		wantAuth bool
	}{
		{ProfileSafe, false, false},
		{ProfileSandbox, true, true},
		{ProfileStaging, true, true},
		{ProfileAuthorizedLive, true, true},
	}
	for _, tc := range tests {
		if got := tc.p.AllowsNetwork(); got != tc.wantNet {
			t.Errorf("%s.AllowsNetwork()=%v want %v", tc.p, got, tc.wantNet)
		}
		if got := tc.p.RequiresAuthorization(); got != tc.wantAuth {
			t.Errorf("%s.RequiresAuthorization()=%v want %v", tc.p, got, tc.wantAuth)
		}
		if tc.p.Describe() == "" {
			t.Errorf("%s.Describe() is empty", tc.p)
		}
	}
}

func TestBudgetExhausted(t *testing.T) {
	b := Budget{Attempts: 3, NetworkRequests: 5, ModelCalls: 5, ToolInvocations: 2, Duration: time.Minute}
	tests := []struct {
		name      string
		spend     Spend
		wantTrip  bool
		wantLimit string
	}{
		{"empty", Spend{}, false, ""},
		{"attempts", Spend{Attempts: 3}, true, "attempts"},
		{"network", Spend{NetworkRequests: 5}, true, "network_requests"},
		{"tools", Spend{ToolInvocations: 2}, true, "tool_invocations"},
		{"duration", Spend{Elapsed: time.Minute}, true, "duration"},
		{"under", Spend{Attempts: 2, NetworkRequests: 4}, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			trip, limit := b.Exhausted(tc.spend)
			if trip != tc.wantTrip || limit != tc.wantLimit {
				t.Errorf("Exhausted(%+v)=(%v,%q) want (%v,%q)", tc.spend, trip, limit, tc.wantTrip, tc.wantLimit)
			}
		})
	}
}

func TestBudgetZeroLimitIsUnbounded(t *testing.T) {
	b := Budget{Attempts: 0}
	if trip, _ := b.Exhausted(Spend{Attempts: 1_000_000}); trip {
		t.Error("a zero Attempts limit must be unbounded")
	}
}

// The wall-clock budget must actually stop a run. Before the Clock hook
// existed, --max-duration parsed fine, was stored, and did nothing — a silent
// no-op limit on a capability that sends attack traffic.
func TestDurationBudgetStopsARun(t *testing.T) {
	tick := 0
	// Each call advances 10s, so the third probe is past a 15s budget.
	clock := func() time.Time {
		tick++
		return time.Unix(0, 0).Add(time.Duration(tick) * 10 * time.Second)
	}

	cs := MintCanaries("clock-seed")
	tgt := newFakeTarget(modeFixed, cs)

	plan := &Plan{
		SchemaVersion: planSchemaVersion,
		Root:          ".",
		Hypotheses: []Hypothesis{
			{ID: "h1", ScenarioID: ScenarioPIDirect, Objective: "obey an injected instruction"},
			{ID: "h2", ScenarioID: ScenarioPIIndirect, Objective: "obey retrieved content"},
		},
	}

	cfg := RunConfig{
		Profile:    ProfileSandbox,
		Authorized: true,
		Budget:     Budget{Attempts: 1000, NetworkRequests: 1000, Duration: 15 * time.Second},
		Seed:       "clock-seed",
		Now:        "2026-08-23T00:00:00Z",
		Route:      "/chat",
		Fields:     []string{"persona", "message"},
		Clock:      clock,
	}

	res, err := Run(context.Background(), plan, tgt, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.BudgetStop == "" {
		t.Fatal("the run should have stopped on the wall-clock budget, but BudgetStop is empty")
	}
	if !strings.Contains(strings.ToLower(res.BudgetStop), "duration") {
		t.Errorf("BudgetStop = %q, want it to name the duration limit", res.BudgetStop)
	}
	// A run cut short by a budget is INCONCLUSIVE, never PREVENTED.
	for i := range res.Traces {
		if res.Traces[i].Exploitability == evidence.Prevented {
			t.Errorf("trace %s is PREVENTED after a budget stop; it must be INCONCLUSIVE", res.Traces[i].ID)
		}
	}
}

// With no clock injected the engine stays pure: a duration budget is inert and
// the run completes, so tests remain deterministic.
func TestWithoutAClockDurationIsInert(t *testing.T) {
	cs := MintCanaries("clock-seed")
	plan := &Plan{
		SchemaVersion: planSchemaVersion,
		Root:          ".",
		Hypotheses:    []Hypothesis{{ID: "h1", ScenarioID: ScenarioPIDirect, Objective: "obey"}},
	}
	cfg := RunConfig{
		Profile:    ProfileSandbox,
		Authorized: true,
		Budget:     Budget{Attempts: 1000, NetworkRequests: 1000, Duration: time.Nanosecond},
		Seed:       "clock-seed",
		Now:        "2026-08-23T00:00:00Z",
		Route:      "/chat",
		Fields:     []string{"persona"},
	}
	res, err := Run(context.Background(), plan, newFakeTarget(modeFixed, cs), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.BudgetStop != "" {
		t.Errorf("with no Clock the duration budget must be inert, got BudgetStop=%q", res.BudgetStop)
	}
}
