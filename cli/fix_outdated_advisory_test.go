package main

import (
	"context"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox-core/vulnsource"
)

// fakeAdvisories answers Lookup from a fixed table keyed "ecosystem name
// version", and records every query it was asked so a test can assert what
// the currency pass actually checked.
type fakeAdvisories struct {
	affected map[string][]string
	asked    []vulnsource.Query
	degrade  *degrade.Degradations
}

func (f *fakeAdvisories) Name() string { return "fake" }

func (f *fakeAdvisories) Lookup(_ context.Context, qs []vulnsource.Query) (map[int][]vulnsource.Record, error) {
	f.asked = append(f.asked, qs...)
	if f.degrade != nil {
		f.degrade.Add(degrade.OSV, "fake: advisory source unreachable", "upgrade targets unchecked")
	}
	out := map[int][]vulnsource.Record{}
	for i, q := range qs {
		for _, id := range f.affected[q.Ecosystem+" "+q.Name+" "+q.Version] {
			out[i] = append(out[i], vulnsource.Record{ID: id})
		}
	}
	return out, nil
}

func grpcAndOpenAI() []upgradeAction {
	return []upgradeAction{
		{ruleID: "OUTDATED", pkg: "google.golang.org/grpc", fromVer: "v1.83.2", toVersion: "v1.84.0", ecosystem: "go", action: goGetBase},
		{ruleID: "OUTDATED", pkg: "github.com/openai/openai-go/v3", fromVer: "v3.62.0", toVersion: "v3.64.0", ecosystem: "go", action: goGetBase},
	}
}

// The regression this exists for: #699 moved grpc from 1.83.2, which is patched
// against GO-2026-6443, to 1.84.0, which is not. "Newer" is not "safer", and a
// currency bump into a known advisory is a vulnerability the tool introduced.
func TestACurrencyBumpIntoAKnownAdvisoryIsHeld(t *testing.T) {
	deg := &degrade.Degradations{}
	src := &fakeAdvisories{affected: map[string][]string{
		"go google.golang.org/grpc 1.84.0": {"GO-2026-6443", "GHSA-2v4p-qf9q-27wj"},
	}}
	kept, held, ok := holdAffectedTargets(context.Background(), src, deg, grpcAndOpenAI())
	if !ok {
		t.Fatal("a clean lookup must not be reported as incomplete")
	}
	if len(kept) != 1 || kept[0].pkg != "github.com/openai/openai-go/v3" {
		t.Errorf("only the unaffected upgrade should survive; kept %+v", kept)
	}
	if len(held) != 1 || !strings.Contains(held[0], "google.golang.org/grpc") ||
		!strings.Contains(held[0], "GO-2026-6443") {
		t.Errorf("the held upgrade must name the package and the advisory; held %v", held)
	}
}

// OSV spells Go versions without the leading v; asking for "v1.84.0" matches
// nothing and would pass every target as clean.
func TestTheTargetVersionIsWhatIsAsked(t *testing.T) {
	src := &fakeAdvisories{}
	holdAffectedTargets(context.Background(), src, &degrade.Degradations{}, grpcAndOpenAI())
	if len(src.asked) != 2 {
		t.Fatalf("expected one query per upgrade, got %+v", src.asked)
	}
	q := src.asked[0]
	if q.Ecosystem != "go" || q.Name != "google.golang.org/grpc" || q.Version != "1.84.0" {
		t.Errorf("must ask about the TARGET version, unprefixed; asked %+v", q)
	}
}

// An advisory source that could not answer is not a clean answer. A currency
// bump is optional, so when its target cannot be checked, nothing is applied.
func TestAnUncheckableTargetIsNotApplied(t *testing.T) {
	deg := &degrade.Degradations{}
	src := &fakeAdvisories{degrade: deg}
	kept, _, ok := holdAffectedTargets(context.Background(), src, deg, grpcAndOpenAI())
	if ok {
		t.Error("a degraded lookup must be reported as incomplete")
	}
	if len(kept) != 0 {
		t.Errorf("nothing may be applied when targets could not be checked; kept %+v", kept)
	}
}
