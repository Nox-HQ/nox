package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox-core/vulnsource"
	osvsource "github.com/nox-hq/nox-core/vulnsource/osv"
)

// A currency bump moves a dependency to the newest version, and newest is not
// safest. #699 moved grpc from 1.83.2, which is patched against GO-2026-6443,
// to 1.84.0, which is not: 1.84.0 was the newest stable release and the fix
// existed only on a development branch. Every version bumper that asks "is
// there something newer?" and nothing else makes that move, and a security
// tool making it has introduced the vulnerability it exists to find.
//
// So each upgrade TARGET is looked up before anything is applied, against the
// same advisory source the scan uses. A target with a known advisory is held,
// and the line saying so names it.

// advisorySource builds the source consulted for upgrade targets. A variable so
// tests can substitute one without a network.
var advisorySource = func(deg *degrade.Degradations) vulnsource.Source {
	return osvsource.New("https://api.osv.dev", &http.Client{Timeout: 30 * time.Second}, deg)
}

// holdAffectedTargets splits actions into those whose target version has no
// known advisory and a description of each one held because it does.
//
// ok is false when the source could not answer: an error, or a blocking
// degradation recorded during the lookup. Then NOTHING is kept. A currency
// bump is optional, and an unchecked target reported as clean is the false
// all-clear this check exists to prevent.
func holdAffectedTargets(ctx context.Context, src vulnsource.Source, deg *degrade.Degradations, actions []upgradeAction) (kept []upgradeAction, held []string, ok bool) {
	if len(actions) == 0 {
		return nil, nil, true
	}
	before := len(deg.Items())
	qs := make([]vulnsource.Query, len(actions))
	for i, a := range actions {
		qs[i] = vulnsource.Query{Ecosystem: a.ecosystem, Name: a.pkg, Version: targetVersion(a)}
	}
	found, err := src.Lookup(ctx, qs)
	if err != nil || blockingSince(deg, before) {
		return nil, nil, false
	}
	for i, a := range actions {
		recs := found[i]
		if len(recs) == 0 {
			kept = append(kept, a)
			continue
		}
		ids := make([]string, len(recs))
		for j, r := range recs {
			ids[j] = r.ID
		}
		held = append(held, fmt.Sprintf("%s %s -> %s: the target is affected by %s",
			a.pkg, a.fromVer, a.toVersion, strings.Join(ids, ", ")))
	}
	return kept, held, true
}

// targetVersion is the version OSV is asked about. OSV spells Go module
// versions without the leading v; asking for "v1.84.0" matches no advisory and
// would pass every target as clean.
func targetVersion(a upgradeAction) string {
	if a.ecosystem == "go" {
		return strings.TrimPrefix(a.toVersion, "v")
	}
	return a.toVersion
}

// blockingSince reports whether a blocking degradation was recorded after the
// first `before` items.
func blockingSince(deg *degrade.Degradations, before int) bool {
	items := deg.Items()
	for _, d := range items[before:] {
		if d.Blocks() {
			return true
		}
	}
	return false
}
