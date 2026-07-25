package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// usesRe matches a GitHub Actions `uses:` pin in a workflow file:
//
//   - uses: actions/checkout@<ref>            # v4
//     uses: owner/repo/sub@<ref>
//
// Groups: 1=leading (indent + "uses: "), 2=owner/repo(/sub), 3=ref
// (a SHA or a tag), 4=trailing comment (optional, e.g. " # v4").
var usesRe = regexp.MustCompile(`^(\s*(?:-\s+)?uses:\s*)([A-Za-z0-9._-]+/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._/-]+)?)@([A-Za-z0-9._-]+)(\s*#.*)?$`)

// isReusableWorkflowRef reports whether a `uses:` target is a reusable
// WORKFLOW rather than an action.
//
// These must keep their tag. slsa-verifier resolves a trusted builder's
// identity from the ref, so pinning slsa-github-generator by digest makes it
// unverifiable; upstream is explicit that its builders "MUST be referenced by
// tag ... contrary to the GitHub best practice for third-party actions ... but
// intentional due to limits in GitHub Actions". Pinning it anyway removed SLSA
// provenance from six nox releases, and did so quietly: every job except
// `final` still reported success.
//
// GitHub requires reusable workflows to live in .github/workflows/, which is
// what distinguishes them from an action published in a subdirectory such as
// anchore/sbom-action/download-syft — that one is an action and stays pinned.
func isReusableWorkflowRef(full string) bool {
	return strings.Contains(full, "/.github/workflows/")
}

// actionPin is one `uses:` occurrence found in a workflow file.
type actionPin struct {
	file    string
	repo    string // owner/repo (subpath stripped for version lookup)
	full    string // owner/repo(/sub) as written
	ref     string // pinned ref (SHA or tag)
	comment string // trailing comment, e.g. " # v4" ("" if none)
	lineNo  int
	prefix  string // the `uses:` line's leading portion (indent + "uses: ")
}

// currentVersion is the version the pin currently tracks: the trailing
// `# vX` comment when the ref is a SHA, else the ref itself when it is a
// tag. Empty when neither yields a version (e.g. a bare-branch pin).
func (p *actionPin) currentVersion() string {
	if v := commentVersion(p.comment); v != "" {
		return v
	}
	if looksLikeVersion(p.ref) {
		return p.ref
	}
	return ""
}

var commentVerRe = regexp.MustCompile(`v?\d+(?:\.\d+){0,2}`)

// releaseTagRe matches a tag that denotes a RELEASE — the whole tag, not a
// prefix of it.
//
// commentVerRe is a substring match, which is right for pulling a version out
// of a trailing comment but wrong for deciding whether a tag is a release:
// `v2.1.0-rc.3` contains `v2.1.0`, so it passed. It then parsed to [2,1,0]
// because parseVer discards the suffix, TIEING the real v2.1.0 — and the
// specificity tiebreak counts dotted components, of which the candidate has
// four to the release's three, so the RELEASE CANDIDATE was judged more
// specific and won. `nox fix --actions` duly replaced a stable @v2.1.0 with a
// release candidate's commit in the workflow that generates this project's
// SLSA provenance. Anchored, so a prerelease or build-metadata suffix is
// simply not a release.
var releaseTagRe = regexp.MustCompile(`^v?\d+(?:\.\d+){0,2}$`)

func commentVersion(comment string) string {
	return commentVerRe.FindString(comment)
}

func looksLikeVersion(ref string) bool {
	return commentVerRe.MatchString(ref) && !isSHA(ref)
}

func isSHA(ref string) bool {
	if len(ref) < 7 {
		return false
	}
	for _, c := range ref {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

// actionResolver returns the latest release tag and its commit SHA for an
// action repo, and the commit SHA a specific tag resolves to. Injected so the
// planning/rewrite logic is testable without the network.
type actionResolver interface {
	latest(repo string) (tag, sha string, err error)
	tagSHA(repo, tag string) (sha string, err error)
}

// runActionsFix scans workflows under root, rewrites outdated action pins to
// the latest release pinned by SHA (`@<sha> # <tag>`), and returns how many
// were applied/skipped. Major-version jumps are skipped unless includeMajor.
func runActionsFix(root string, dryRun, includeMajor bool, r actionResolver) (applied, skipped, failed int) {
	pins := collectActionPins(root)
	if len(pins) == 0 {
		return 0, 0, 0
	}

	// Resolve each unique repo's latest release once.
	type latest struct {
		tag, sha string
		ok       bool
	}
	cache := map[string]latest{}
	resolve := func(repo string) latest {
		if l, seen := cache[repo]; seen {
			return l
		}
		tag, sha, err := r.latest(repo)
		l := latest{tag: tag, sha: sha, ok: err == nil && tag != "" && sha != ""}
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: resolve %s: %v\n", repo, err)
		}
		cache[repo] = l
		return l
	}
	// Resolve a specific tag's commit SHA once (for SHA-pinning a mutable tag
	// in place when the latest release is a major we won't jump to).
	tagCache := map[string]string{}
	resolveTag := func(repo, tag string) string {
		key := repo + "@" + tag
		if s, seen := tagCache[key]; seen {
			return s
		}
		sha, err := r.tagSHA(repo, tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: resolve %s@%s: %v\n", repo, tag, err)
			sha = ""
		}
		tagCache[key] = sha
		return sha
	}

	// Group rewrites per file so each file is read/written once.
	perFile := map[string][]rewrite{}
	for _, p := range pins {
		// A reusable workflow keeps its tag: pinning it by digest makes it
		// unverifiable to slsa-verifier. See isReusableWorkflowRef.
		if isReusableWorkflowRef(p.full) {
			skipped++
			continue
		}
		cur := p.currentVersion()
		if cur == "" {
			skipped++ // tracks a branch (e.g. @main reusable workflow) — leave it
			continue
		}
		l := resolve(p.repo)
		if !l.ok {
			skipped++
			continue
		}

		// A mutable ref (a tag like @v7, i.e. not a hex commit SHA per isSHA)
		// must be pinned to a SHA even when it already tracks the latest
		// version — that is the whole point of pinning (supply-chain
		// immutability). An already-SHA ref only needs touching when it is
		// genuinely outdated.
		mutable := !isSHA(p.ref)
		outdated := versionLess(cur, l.tag)
		sameMajor := majorComponent(cur) == majorComponent(l.tag)

		var tag, sha, why string
		switch {
		case outdated && (includeMajor || sameMajor):
			// Upgrade to the latest release, SHA-pinned.
			tag, sha, why = l.tag, l.sha, fmt.Sprintf("%s -> %s", cur, l.tag)
		case outdated && mutable:
			// Newer major exists but we won't jump it; still SHA-pin the
			// mutable tag in place at its current major.
			if s := resolveTag(p.repo, p.ref); s != "" {
				tag, sha, why = p.ref, s, fmt.Sprintf("pin %s (major %d held; latest %s)", p.ref, majorComponent(cur), l.tag)
			} else {
				fmt.Printf("skip (major): %s %s -> %s (use --include-major)\n", p.full, cur, l.tag)
				skipped++
				continue
			}
		case outdated:
			// Already SHA-pinned, newer major available — hold without flag.
			fmt.Printf("skip (major): %s %s -> %s (use --include-major)\n", p.full, cur, l.tag)
			skipped++
			continue
		case mutable && sameMajor:
			// Up to date but mutable → SHA-pin to the same-major latest.
			tag, sha, why = l.tag, l.sha, fmt.Sprintf("pin %s", cur)
		case mutable:
			// Up to date, mutable, latest is a different (older) major line —
			// pin the tag to its own SHA without changing the version.
			if s := resolveTag(p.repo, p.ref); s != "" {
				tag, sha, why = p.ref, s, fmt.Sprintf("pin %s", p.ref)
			} else {
				skipped++
				continue
			}
		default:
			// Already SHA-pinned and up to date — nothing to do.
			skipped++
			continue
		}

		if sha == p.ref {
			skipped++ // already pinned to this exact SHA
			continue
		}
		newLine := fmt.Sprintf("%s@%s # %s", p.full, sha, tag)
		perFile[p.file] = append(perFile[p.file], rewrite{lineNo: p.lineNo, prefix: p.prefix, newRest: newLine})
		fmt.Printf("plan: %s %s (%s)\n", p.full, why, short(sha))
	}

	if dryRun {
		for _, rs := range perFile {
			applied += len(rs)
		}
		return applied, skipped, failed
	}
	for file, rs := range perFile {
		if err := applyRewrites(file, rs); err != nil {
			fmt.Fprintf(os.Stderr, "error: rewrite %s: %v\n", file, err)
			failed += len(rs)
			continue
		}
		applied += len(rs)
	}
	return applied, skipped, failed
}

type rewrite struct {
	lineNo  int
	prefix  string
	newRest string
}

// collectActionPins walks .github/workflows under root and returns every
// `uses:` pin. Composite-action files (action.yml) are included too.
func collectActionPins(root string) []actionPin {
	var pins []actionPin
	dirs := []string{filepath.Join(root, ".github", "workflows")}
	// composite actions live under .github/actions/*/action.yml
	dirs = append(dirs, filepath.Join(root, ".github", "actions"))
	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if ext := filepath.Ext(path); ext != ".yml" && ext != ".yaml" {
				return nil
			}
			pins = append(pins, parsePins(root, path)...)
			return nil
		})
	}
	return pins
}

func parsePins(root, path string) []actionPin {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []actionPin
	for i, line := range strings.Split(string(data), "\n") {
		m := usesRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		full := m[2]
		repo := full
		if parts := strings.SplitN(full, "/", 3); len(parts) >= 2 {
			repo = parts[0] + "/" + parts[1]
		}
		out = append(out, actionPin{
			file:    path,
			repo:    repo,
			full:    full,
			ref:     m[3],
			comment: strings.TrimRight(m[4], "\r"),
			lineNo:  i,
			prefix:  m[1],
		})
	}
	return out
}

func applyRewrites(file string, rs []rewrite) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	for _, rw := range rs {
		if rw.lineNo < 0 || rw.lineNo >= len(lines) {
			continue
		}
		lines[rw.lineNo] = rw.prefix + rw.newRest
	}
	return os.WriteFile(file, []byte(strings.Join(lines, "\n")), 0o644)
}

// --- version comparison ----------------------------------------------------

// versionLess reports whether a < b for vX[.Y[.Z]] version strings. Missing
// components are treated as 0, so v6 < v6.5.0.
func versionLess(a, b string) bool {
	return cmpVersion(a, b) < 0
}

func cmpVersion(a, b string) int {
	pa, pb := parseVer(a), parseVer(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseVer(v string) [3]int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	var out [3]int
	for i, seg := range strings.SplitN(v, ".", 3) {
		if i > 2 {
			break
		}
		n, _ := strconv.Atoi(strings.TrimFunc(seg, func(r rune) bool { return r < '0' || r > '9' }))
		out[i] = n
	}
	return out
}

func majorComponent(v string) int { return parseVer(v)[0] }

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// --- GitHub resolver -------------------------------------------------------

// githubResolver resolves an action's latest release tag + commit SHA via the
// GitHub REST API. A token (GITHUB_TOKEN / GH_TOKEN) lifts the rate limit and
// is required for any non-trivial run.
type githubResolver struct {
	client *http.Client
	token  string
	base   string // API base, overridable in tests
}

func newGithubResolver() *githubResolver {
	tok := os.Getenv("GITHUB_TOKEN")
	if tok == "" {
		tok = os.Getenv("GH_TOKEN")
	}
	return &githubResolver{
		client: &http.Client{Timeout: 15 * time.Second},
		token:  tok,
		base:   "https://api.github.com",
	}
}

func (g *githubResolver) latest(repo string) (tag, sha string, err error) {
	tag, err = g.latestTag(repo)
	if err != nil {
		return "", "", err
	}
	sha, err = g.tagSHA(repo, tag)
	if err != nil {
		return "", "", err
	}
	return tag, sha, nil
}

// latestTag returns the newest version an action actually serves.
//
// It used to return the GitHub Release and stop. Tags were consulted only as a
// fallback "for repos without GitHub Releases". That is the wrong precedence: a
// GitHub Release is an announcement, but an Action is consumed by TAG, so a
// repository that tags v1.0.1 without cutting a Release is already serving
// v1.0.1 to every workflow pinned to @v1.
//
// The consequence was a silent DOWNGRADE. nox-hq/nox-remediate-action has one
// Release (v1.0.0) and tags v1.0.1 and v1; @v1 resolves to v1.0.1's commit.
// `nox fix -actions` read the Release, decided "latest" was v1.0.0, and planned
// to rewrite @v1 to v1.0.0's commit — moving the pinned action BACKWARD while
// labelling it v1. A tool whose purpose is supply-chain pinning must never pin
// to something older than what is already running, least of all silently.
//
// Both sources are now consulted and the newer wins.
func (g *githubResolver) latestTag(repo string) (string, error) {
	best := ""

	// The Release, when present, is the maintainer's explicit statement of what
	// is current, so it seeds the comparison.
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := g.get("/repos/"+repo+"/releases/latest", &rel); err == nil && rel.TagName != "" {
		best = rel.TagName
	}

	var tags []struct {
		Name string `json:"name"`
	}
	if err := g.get("/repos/"+repo+"/tags?per_page=100", &tags); err != nil {
		// Tags unreachable: fall back to the Release rather than failing, since
		// a stale-but-real version beats no answer. Only error when neither
		// source produced anything.
		if best != "" {
			return best, nil
		}
		return "", err
	}
	for _, t := range tags {
		if !releaseTagRe.MatchString(t.Name) {
			continue // prereleases and build metadata are not candidates
		}
		if best == "" || preferTag(best, t.Name) {
			best = t.Name
		}
	}
	if best == "" {
		return "", fmt.Errorf("no version tag found")
	}
	return best, nil
}

// preferTag reports whether candidate should replace current as "latest".
//
// Higher version wins. On an exact version tie it prefers the MORE specific
// tag, so a repo carrying both `v1.0.1` and the moving `v1` pins to v1.0.1 —
// they denote the same commit, but only the specific one still means that
// commit tomorrow, and it is what the pin comment should record.
func preferTag(current, candidate string) bool {
	// A prerelease never outranks a release. latestTag already filters them
	// out, but the ranking primitive must be right on its own: the specificity
	// tiebreak counts dotted components, and `v2.1.0-rc.3` has one more than
	// `v2.1.0`, so without this it declares the release candidate the more
	// specific tag and pins it.
	if cur, cand := releaseTagRe.MatchString(current), releaseTagRe.MatchString(candidate); cur != cand {
		return cand // prefer the candidate only when IT is the release
	}
	switch cmpVersion(current, candidate) {
	case -1:
		return true
	case 1:
		return false
	}
	return specificity(candidate) > specificity(current)
}

// specificity counts the dotted components in a version tag: v1 → 1, v1.0 → 2,
// v1.0.1 → 3.
func specificity(tag string) int {
	return len(strings.Split(strings.TrimPrefix(strings.TrimSpace(tag), "v"), "."))
}

func (g *githubResolver) tagSHA(repo, tag string) (string, error) {
	var c struct {
		SHA string `json:"sha"`
	}
	if err := g.get("/repos/"+repo+"/commits/"+tag, &c); err != nil {
		return "", err
	}
	return c.SHA, nil
}

func (g *githubResolver) get(path string, v any) error {
	req, err := http.NewRequest(http.MethodGet, g.base+path, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}
