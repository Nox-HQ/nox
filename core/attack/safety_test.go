package attack

import (
	"testing"
	"time"
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
