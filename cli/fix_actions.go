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
// action repo. Injected so the planning/rewrite logic is testable without
// the network.
type actionResolver interface {
	latest(repo string) (tag, sha string, err error)
}

// runActionsFix scans workflows under root, rewrites outdated action pins to
// the latest release pinned by SHA (`@<sha> # <tag>`), and returns how many
// were applied/skipped. Major-version jumps are skipped unless includeMajor.
func runActionsFix(root string, dryRun, includeMajor bool, r actionResolver) (applied, skipped, failed int) {
	pins := collectActionPins(root)
	if len(pins) == 0 {
		return 0, 0, 0
	}

	// Resolve each unique repo once.
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

	// Group rewrites per file so each file is read/written once.
	perFile := map[string][]rewrite{}
	for _, p := range pins {
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
		if !versionLess(cur, l.tag) {
			skipped++ // already latest (or ahead)
			continue
		}
		if !includeMajor && majorComponent(cur) != majorComponent(l.tag) {
			fmt.Printf("skip (major): %s %s -> %s (use --include-major)\n", p.full, cur, l.tag)
			skipped++
			continue
		}
		newLine := fmt.Sprintf("%s@%s # %s", p.full, l.sha, l.tag)
		perFile[p.file] = append(perFile[p.file], rewrite{lineNo: p.lineNo, prefix: p.prefix, newRest: newLine})
		fmt.Printf("plan: %s %s -> %s (%s)\n", p.full, cur, l.tag, short(l.sha))
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

func (g *githubResolver) latestTag(repo string) (string, error) {
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := g.get("/repos/"+repo+"/releases/latest", &rel); err == nil && rel.TagName != "" {
		return rel.TagName, nil
	}
	// Fallback: newest tag (repos without GitHub Releases).
	var tags []struct {
		Name string `json:"name"`
	}
	if err := g.get("/repos/"+repo+"/tags?per_page=100", &tags); err != nil {
		return "", err
	}
	best := ""
	for _, t := range tags {
		if commentVerRe.MatchString(t.Name) && (best == "" || versionLess(best, t.Name)) {
			best = t.Name
		}
	}
	if best == "" {
		return "", fmt.Errorf("no version tag found")
	}
	return best, nil
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
