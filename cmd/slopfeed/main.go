// Command slopfeed generates the predictive slopsquat blocklist that nox's SLOP
// analyzer consumes offline. It is a thin command line over
// github.com/nox-hq/nox-core/slopfeed/generate, which holds the candidate
// model, the registry checker and the scoring: it models how LLMs hallucinate
// package names, generates the names they are likely to emit, checks public
// registries read-only (rate-limited, re-verifying every 404), and writes only
// names that are BOTH high-likelihood AND currently unregistered, never
// accusing a registered package.
//
// Only this tool touches the network; the scanner consumes the frozen, signed,
// content-addressed artifact it writes. See docs/slopsquat-feed.md.
//
// The weekly publish workflow runs it until the nox-intelligence service
// publishes the feed itself.
//
// Usage:
//
//	slopfeed --out core/analyzers/slop/feed/data/slopsquat-blocklist.v1.json \
//	         --limit 180 --sleep 400ms --version 2026.07.25
//	slopfeed --dry-run          # generate candidates only, no network
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/nox-hq/nox-core/slopfeed"
	"github.com/nox-hq/nox-core/slopfeed/generate"
)

// feedSource is the generator identity recorded in feeds this command writes.
const feedSource = "cmd/slopfeed"

func main() {
	var (
		out      = flag.String("out", "core/analyzers/slop/feed/data/slopsquat-blocklist.v1.json", "output feed path")
		limit    = flag.Int("limit", generate.DefaultLimit, "max candidates to check against registries (stratified across patterns)")
		sleep    = flag.Duration("sleep", generate.DefaultInterval, "delay between registry requests (politeness)")
		version  = flag.String("version", time.Now().UTC().Format("2006.01.02"), "feed version string")
		dryRun   = flag.Bool("dry-run", false, "generate + select candidates but make no network calls; print a summary")
		timeout  = flag.Duration("timeout", generate.DefaultRequestTimeout, "per-request HTTP timeout")
		printTop = flag.Int("print", 20, "print the top-N produced entries to stderr")
		signKey  = flag.String("sign-key", "", "PEM Ed25519 private key (PKCS#8 or raw) used to sign the feed; when set, the written feed carries an Ed25519 signature over its canonical bytes")
		keyID    = flag.String("key-id", "", "free-form identifier recorded in the signature (key rotation / audit)")
		pubOut   = flag.String("pubkey-out", "", "path to write the signer's public key PEM; defaults to <out>.pub.pem when --sign-key is set")
	)
	flag.Parse()

	opts := runOptions{
		out: *out, limit: *limit, sleep: *sleep, timeout: *timeout, version: *version,
		dryRun: *dryRun, printTop: *printTop, signKey: *signKey, keyID: *keyID, pubOut: *pubOut,
	}
	if err := run(opts); err != nil {
		fmt.Fprintln(os.Stderr, "slopfeed:", err)
		os.Exit(1)
	}
}

// runOptions bundles the generator's parameters.
type runOptions struct {
	out            string
	limit          int
	sleep, timeout time.Duration
	version        string
	dryRun         bool
	printTop       int
	signKey, keyID string
	pubOut         string
}

func run(o runOptions) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// --limit 0 (or below) has always meant "check every candidate"; in the
	// library a zero limit means the default, so pass a negative one.
	limit := o.limit
	if limit <= 0 {
		limit = -1
	}
	cands := generate.Candidates()
	selected := generate.Select(cands, limit)
	fmt.Fprintf(os.Stderr, "generated %d candidates; checking %d (stratified)\n", len(cands), len(selected))

	if o.dryRun {
		summarize(selected)
		return nil
	}

	f, rep, err := generateFeed(ctx, o, limit)
	if err != nil {
		return err
	}

	// Sign the feed when a signing key is provided. Sign re-derives the digest
	// over the canonical entry bytes and attaches the Ed25519 signature nox
	// verifies against a pinned public key. The public key is written next to the
	// feed so the publish pipeline can attach it as a downloadable trust anchor.
	if o.signKey != "" {
		pubOut := o.pubOut
		if pubOut == "" {
			pubOut = o.out + ".pub.pem"
		}
		if err := signFeed(f, o.signKey, o.keyID, pubOut); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "signed feed with key %q (public key -> %s)\n", o.keyID, pubOut)
	}

	data, err := slopfeed.Encode(f)
	if err != nil {
		return err
	}
	if err := os.WriteFile(o.out, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", o.out, err)
	}

	fmt.Fprintf(os.Stderr,
		"\nwrote %s\n  entries: %d  (unregistered %d / registered %d / inconclusive %d)\n  requests: %d  digest: %s\n",
		o.out, len(f.Entries), rep.Unregistered, rep.Registered, rep.Inconclusive, rep.Requests, f.Digest)
	printTopEntries(f.Entries, o.printTop)
	return nil
}

// generateFeed checks the selected candidates against the registries and
// assembles the feed, reporting progress every 25 names.
func generateFeed(ctx context.Context, o runOptions, limit int) (*slopfeed.Feed, generate.Report, error) {
	// A non-positive --sleep has always meant "no pause"; the library spells
	// that as a negative interval, since zero selects its default.
	interval := o.sleep
	if interval <= 0 {
		interval = -1
	}
	chk := generate.NewChecker(generate.CheckerOptions{
		Client:   &http.Client{Timeout: o.timeout},
		Interval: interval,
	})
	f, rep, err := generate.Feed(ctx, generate.Options{
		Checker: chk,
		Limit:   limit,
		Version: o.version,
		Source:  feedSource,
		Progress: func(checked, total int) {
			if checked%25 == 0 {
				fmt.Fprintf(os.Stderr, "  checked %d/%d (%d requests)\n", checked, total, chk.Requests())
			}
		},
	})
	if err != nil {
		return nil, rep, err
	}
	// The feed has always been stamped when the run finished. GeneratedAt is
	// metadata outside the digest, so restamping it changes no verified byte.
	f.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	return f, rep, nil
}

// signFeed signs f in place with the key at keyPath and writes the matching
// public key PEM to pubkeyOut.
func signFeed(f *slopfeed.Feed, keyPath, keyID, pubkeyOut string) error {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("reading signing key: %w", err)
	}
	priv, err := slopfeed.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return fmt.Errorf("signing key %s: %w", keyPath, err)
	}
	if err := f.Sign(priv, keyID); err != nil {
		return fmt.Errorf("signing feed: %w", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("deriving public key")
	}
	if err := os.WriteFile(pubkeyOut, []byte(slopfeed.EncodePublicKeyPEM(pub)), 0o644); err != nil {
		return fmt.Errorf("writing public key %s: %w", pubkeyOut, err)
	}
	return nil
}

func printTopEntries(entries []slopfeed.Entry, n int) {
	if n > len(entries) {
		n = len(entries)
	}
	for _, e := range entries[:max(n, 0)] {
		fmt.Fprintf(os.Stderr, "  %.2f %-8s %-4s %s\n", e.Risk, e.Tier, e.Ecosystem, e.Name)
	}
}

func summarize(selected []generate.Candidate) {
	byPat, byEco := map[string]int{}, map[string]int{}
	for _, c := range selected {
		byPat[c.Pattern]++
		byEco[c.Ecosystem]++
	}
	fmt.Fprintf(os.Stderr, "selected by pattern: %v\n", byPat)
	fmt.Fprintf(os.Stderr, "selected by ecosystem: %v\n", byEco)
	n := min(15, len(selected))
	for _, c := range selected[:n] {
		fmt.Fprintf(os.Stderr, "  %.3f [%s/%s] %s\n", c.Prior, c.Ecosystem, c.Pattern, c.Name)
	}
}
