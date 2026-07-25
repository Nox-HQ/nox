// Command slopfeed generates the predictive slopsquat blocklist that nox's SLOP
// analyzer consumes offline. It is the maintained port of the research
// prototype (scratchpad/research/slopsquat): it models how LLMs hallucinate
// package names, generates the names they are likely to emit, checks public
// registries read-only (rate-limited, re-verifying every 404), and writes only
// names that are BOTH high-likelihood AND currently unregistered — never
// accusing a registered package.
//
// Only this tool touches the network; the scanner consumes the frozen, signed,
// content-addressed artifact it writes. See docs/slopsquat-feed.md.
//
// Usage:
//
//	slopfeed --out core/analyzers/slop/feed/data/slopsquat-blocklist.v1.json \
//	         --limit 180 --sleep 400ms --version 2026.07.25
//	slopfeed --dry-run          # generate candidates only, no network
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"time"

	"github.com/nox-hq/nox/core/analyzers/slop/feed"
)

func main() {
	var (
		out      = flag.String("out", "core/analyzers/slop/feed/data/slopsquat-blocklist.v1.json", "output feed path")
		limit    = flag.Int("limit", 180, "max candidates to check against registries (stratified across patterns)")
		sleep    = flag.Duration("sleep", 400*time.Millisecond, "delay between registry requests (politeness)")
		version  = flag.String("version", time.Now().UTC().Format("2006.01.02"), "feed version string")
		dryRun   = flag.Bool("dry-run", false, "generate + select candidates but make no network calls; print a summary")
		timeout  = flag.Duration("timeout", 20*time.Second, "per-request HTTP timeout")
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

// runOptions bundles the generator's parameters. It grew past a comfortable
// positional-argument count once signing was added.
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

	cands := generateCandidates()
	selected := stratifiedSelect(cands, o.limit)
	fmt.Fprintf(os.Stderr, "generated %d candidates; checking %d (stratified)\n", len(cands), len(selected))

	if o.dryRun {
		summarize(selected)
		return nil
	}

	chk := newChecker(&http.Client{Timeout: o.timeout}, o.sleep)
	today := time.Now().UTC().Format("2006-01-02")

	var (
		entries []feed.Entry
		nUnreg  int
		nReg    int
		nInconc int
	)
	for i, c := range selected {
		if err := ctx.Err(); err != nil {
			return err
		}
		r := chk.check(ctx, c.name, c.ecosystem)
		switch r.verdict {
		case unregistered:
			nUnreg++
			if e, ok := scoreSquattable(c, r, today); ok {
				entries = append(entries, e)
			}
		case registered:
			nReg++
		default:
			nInconc++
		}
		if (i+1)%25 == 0 {
			fmt.Fprintf(os.Stderr, "  checked %d/%d (%d requests)\n", i+1, len(selected), chk.requests)
		}
	}

	// Deterministic ordering in the written file: highest risk first.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Risk != entries[j].Risk {
			return entries[i].Risk > entries[j].Risk
		}
		if entries[i].Ecosystem != entries[j].Ecosystem {
			return entries[i].Ecosystem < entries[j].Ecosystem
		}
		return entries[i].Name < entries[j].Name
	})

	f := &feed.Feed{
		SchemaVersion: feed.SchemaVersion,
		Version:       o.version,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Source:        "cmd/slopfeed",
		Entries:       entries,
	}
	f.SetDigest()

	// Sign the feed when a signing key is provided. Sign re-derives the digest
	// over the canonical entry bytes and attaches the Ed25519 signature nox
	// verifies against a pinned public key. The public key is written next to the
	// feed so the publish pipeline can attach it as a downloadable trust anchor.
	if o.signKey != "" {
		pubOut := o.pubOut
		if pubOut == "" {
			pubOut = o.out + ".pub.pem"
		}
		if _, err := signFeed(f, o.signKey, o.keyID, pubOut); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "signed feed with key %q (public key -> %s)\n", o.keyID, pubOut)
	}

	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling feed: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(o.out, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", o.out, err)
	}

	fmt.Fprintf(os.Stderr,
		"\nwrote %s\n  entries: %d  (unregistered %d / registered %d / inconclusive %d)\n  requests: %d  digest: %s\n",
		o.out, len(entries), nUnreg, nReg, nInconc, chk.requests, f.Digest)
	if o.printTop > 0 {
		n := o.printTop
		if n > len(entries) {
			n = len(entries)
		}
		for _, e := range entries[:n] {
			fmt.Fprintf(os.Stderr, "  %.2f %-8s %-4s %s\n", e.Risk, e.Tier, e.Ecosystem, e.Name)
		}
	}
	return nil
}

// stratifiedSelect takes the highest-prior slice of each pattern so every
// research class (obvious / typo / composition) gets real registry coverage
// rather than one class dominating the budget. Mirrors the prototype harness.
func stratifiedSelect(cands []candidate, limit int) []candidate {
	if limit <= 0 || limit >= len(cands) {
		return cands
	}
	quota := map[string]int{"obvious": 40, "typo": 70, "composition": 70}
	byPat := map[string][]candidate{}
	for _, c := range cands {
		byPat[c.pattern] = append(byPat[c.pattern], c)
	}
	seen := map[string]struct{}{}
	var out []candidate
	for _, pat := range []string{"obvious", "typo", "composition"} {
		list := byPat[pat] // already prior-sorted (generateCandidates sorts globally)
		q := quota[pat]
		for i := 0; i < len(list) && i < q && len(out) < limit; i++ {
			key := list[i].ecosystem + "\x00" + list[i].name
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, list[i])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].prior > out[j].prior })
	return out
}

func summarize(selected []candidate) {
	byPat, byEco := map[string]int{}, map[string]int{}
	for _, c := range selected {
		byPat[c.pattern]++
		byEco[c.ecosystem]++
	}
	fmt.Fprintf(os.Stderr, "selected by pattern: %v\n", byPat)
	fmt.Fprintf(os.Stderr, "selected by ecosystem: %v\n", byEco)
	n := 15
	if n > len(selected) {
		n = len(selected)
	}
	for _, c := range selected[:n] {
		fmt.Fprintf(os.Stderr, "  %.3f [%s/%s] %s\n", c.prior, c.ecosystem, c.pattern, c.name)
	}
}
