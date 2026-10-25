package core

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox-core/slopfeed"
	"github.com/nox-hq/nox/core/analyzers/slop"
	"github.com/nox-hq/nox/core/analyzers/slop/feed"
)

// resolveSlopFeed decides which predictive slopsquat feed, if any, the SLOP
// analyzer gets, and records a degradation for every way it can end up with none.
//
//   - scan.slop.feed set: that feed, exactly as before.
//   - scan.slop.disabled: none, silently (an explicit opt-out).
//   - otherwise: NOX Intelligence's signed feed, verified under the project's
//     pinned key when scan.slop.signature_key_path names one and under the key
//     built into nox when it does not. A signature is required: the service's
//     feed is always signed, so an unsigned answer is a failure, not a feed.
//
// The default consults the network only when the scan is online and the
// intelligence service is enabled. Offline, or with lookups disabled, nothing is
// requested: a verified cached copy is used, and otherwise the scan says the
// feed was not checked and why, so absence of SLOP-002 never reads as "nothing
// high-risk".
func resolveSlopFeed(ctx context.Context, target string, cfg *ScanConfig, opts ScanOptions, deg *degrade.Degradations) []slop.Option { //nolint:gocritic // mirrors RunScanContext
	if !opts.Scopes.Has(ScopeSupplyChain) {
		return nil
	}
	sc := cfg.Scan.Slop
	if sc.Feed != "" {
		return explicitSlopFeed(ctx, target, sc, opts, deg)
	}
	if sc.Disabled {
		return nil
	}
	feedURL := cfg.Scan.Intelligence.DefaultSlopFeedURL()
	if feedURL == "" {
		deg.AddAdvisory(degrade.SlopFeed,
			"the predictive slopsquat feed was not checked: NOX Intelligence is disabled (scan.intelligence.disabled) and scan.slop.feed names no feed",
			"SLOP-002 is off; high-risk slopsquat targets are not flagged from the feed. This is not \"nothing high-risk\"")
		return nil
	}
	noNetwork := opts.Offline || opts.DisableOSV || cfg.Scan.OSV.Disabled

	key, err := resolveFeedKey(target, sc.SignatureKeyPath)
	if err != nil {
		deg.Add(degrade.SlopFeed, fmt.Sprintf("the slopsquat feed key could not be used: %v", err),
			"the SLOP-002 predictive dimension is disabled; high-risk slopsquat targets are not being flagged from the feed")
		return nil
	}
	loaded, err := loadRemoteSlopFeed(ctx, target, sc, feedURL, noNetwork, slopfeed.VerifyOptions{RequireSignature: true, Verifier: key.verify})
	if err != nil {
		recordSlopFeedFailure(ctx, deg, key, feedURL, opts.Offline, noNetwork, err)
		return nil
	}
	return []slop.Option{slop.WithFeed(loaded), slop.WithFeedKey(key.source())}
}

func recordSlopFeedFailure(ctx context.Context, deg *degrade.Degradations, key feedKey, feedURL string, offline, noNetwork bool, err error) {
	const impact = "the SLOP-002 predictive dimension is disabled; high-risk slopsquat targets are not being flagged from the feed. This is not \"nothing high-risk\""
	var np *feed.NotPublishedError
	switch {
	case errors.As(err, &np):
		deg.AddAdvisory(degrade.SlopFeed, "the slopsquat feed is not available from NOX Intelligence: the service has not published one yet", impact)
	case noNetwork:
		why := "network lookups are disabled"
		if offline {
			why = "the scan is offline"
		}
		deg.AddAdvisory(degrade.SlopFeed, fmt.Sprintf("the slopsquat feed was not checked: %s and no verified cached copy exists", why), impact)
	default:
		deg.Add(degrade.SlopFeed, fmt.Sprintf("the slopsquat feed from NOX Intelligence could not be used: %s", explainFeedFailure(ctx, key, feedURL, false, err)), impact)
	}
}

// explicitSlopFeed is the pre-existing behavior for a feed named in .nox.yaml.
func explicitSlopFeed(ctx context.Context, target string, sc SlopConfig, opts ScanOptions, deg *degrade.Degradations) []slop.Option {
	loaded, err := loadSlopFeed(ctx, target, sc, opts.Offline)
	if err != nil {
		deg.Add(degrade.SlopFeed,
			fmt.Sprintf("predictive slopsquat feed %q could not be loaded: %v", sc.Feed, err),
			"the SLOP-002 predictive dimension is disabled; high-risk slopsquat targets are not being flagged from the feed")
		return nil
	}
	return []slop.Option{slop.WithFeed(loaded)}
}

// loadRemoteSlopFeed fetches (or, with no network, reads the verified cache of)
// the feed at url under the given verification.
func loadRemoteSlopFeed(ctx context.Context, target string, sc SlopConfig, url string, noNetwork bool, verify slopfeed.VerifyOptions) (*slopfeed.Loaded, error) {
	ttl := feed.DefaultRefreshInterval
	if sc.Refresh != "" {
		parsed, err := parseFeedRefresh(sc.Refresh)
		if err != nil {
			return nil, fmt.Errorf("parsing slop.refresh %q: %w", sc.Refresh, err)
		}
		ttl = parsed
	}
	cacheDir := sc.CacheDir
	if cacheDir != "" && !filepath.IsAbs(cacheDir) {
		cacheDir = filepath.Join(scanRootDir(target), cacheDir)
	}
	return feed.LoadRemote(ctx, feed.RemoteOptions{URL: url, CacheDir: cacheDir, TTL: ttl, Offline: noNetwork, Verify: verify})
}
