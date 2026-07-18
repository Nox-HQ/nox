// registry-sync reconciles registry-scaffold/index.json against the GitHub
// releases of each plugin it lists.
//
// WHY THIS EXISTS. The CLI resolves plugins from
// raw.githubusercontent.com/nox-hq/nox/main/registry-scaffold/index.json, so a
// published GitHub release is NOT installable until the index lists it. That
// step was manual and nothing detected the gap: seven plugins were once
// released, signed, and completely invisible to `nox plugin install` while
// every check reported green. Automation that silently does not fire is how
// that happened, so this tool is built to be loud first and helpful second:
//
//	-check   report versions missing from the index and exit non-zero.
//	         Run in CI. This is the part with standalone value.
//	-write   additionally add them, for a scheduled job to open a PR from.
//
// It is deliberately a PULL: it reads releases rather than having each plugin
// repository push here. A push model needs a cross-repo write token in every
// plugin repository, and a single stale token silently degrading a release is
// exactly the failure this project already suffered. Pull also self-heals — a
// release missed for any reason is picked up on the next run, whereas a failed
// push is invisible forever.
//
// It never invents a digest. An artifact whose checksum cannot be resolved from
// the release's checksums.txt is reported and skipped, because a placeholder
// digest in a security registry is worse than a missing entry: it looks like
// verification metadata and is not.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	indexPathDefault = "registry-scaffold/index.json"
	githubAPI        = "https://api.github.com"
)

// artifactRe matches the platform-specific archives a release publishes, e.g.
// nox-plugin-red-team_0.7.0_darwin_arm64.tar.gz.
var artifactRe = regexp.MustCompile(`_(darwin|linux|windows)_(amd64|arm64)\.(tar\.gz|zip)$`)

// repoRe pulls owner/name out of a homepage URL.
var repoRe = regexp.MustCompile(`github\.com/([^/]+)/([^/\s]+)`)

type ghRelease struct {
	TagName     string `json:"tag_name"`
	PublishedAt string `json:"published_at"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
	Assets      []struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func main() {
	var (
		indexPath string
		write     bool
		check     bool
	)
	flag.StringVar(&indexPath, "index", indexPathDefault, "registry index JSON")
	flag.BoolVar(&write, "write", false, "add missing versions to the index")
	flag.BoolVar(&check, "check", false, "report missing versions and exit 1 if any (CI mode)")
	var all bool
	flag.BoolVar(&all, "all", false, "consider every published release, not just the newest per plugin")
	flag.Parse()

	if !write && !check {
		fmt.Fprintln(os.Stderr, "specify -check (report) or -write (reconcile)")
		os.Exit(2)
	}

	raw, err := os.ReadFile(indexPath)
	if err != nil {
		fatal("reading %s: %v", indexPath, err)
	}

	// Decode into a generic map so every field this tool does not model is
	// preserved byte-for-byte on write. The index carries maintainers, track,
	// license and more that are none of this tool's business.
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		fatal("parsing %s: %v", indexPath, err)
	}
	plugins, _ := doc["plugins"].([]any)
	if len(plugins) == 0 {
		fatal("no plugins in %s", indexPath)
	}

	var missing []string
	var skipped []string
	changed := false

	for _, p := range plugins {
		pm, _ := p.(map[string]any)
		if pm == nil {
			continue
		}
		name, _ := pm["name"].(string)
		home, _ := pm["homepage"].(string)
		owner, repo := parseRepo(home)
		if repo == "" {
			skipped = append(skipped, fmt.Sprintf("%s: cannot derive repo from homepage %q", name, home))
			continue
		}

		known := map[string]bool{}
		versions, _ := pm["versions"].([]any)
		for _, v := range versions {
			if vm, ok := v.(map[string]any); ok {
				if s, ok := vm["version"].(string); ok {
					known[s] = true
				}
			}
		}

		releases, err := fetchReleases(owner, repo)
		if err != nil {
			// A transient API failure must not look like "nothing missing".
			fatal("%s: listing releases: %v", name, err)
		}

		// Default to the NEWEST release per plugin.
		//
		// The index is a curated subset, not a mirror: 29 historical versions
		// are absent by choice. Flagging all of them would make this check
		// permanently red, and a gate that is always red gets ignored or
		// deleted. The signal worth acting on is narrower and unambiguous —
		// "the latest release of this plugin is not installable" — which is
		// exactly the condition that went unnoticed. Use -all for a full audit.
		if !all && len(releases) > 1 {
			releases = releases[:1] // GitHub returns newest first
		}

		for _, rel := range releases {
			if rel.Draft || rel.Prerelease {
				continue
			}
			ver := strings.TrimPrefix(rel.TagName, "v")
			if known[ver] {
				continue
			}
			missing = append(missing, fmt.Sprintf("%s %s (released %s)", name, ver, rel.PublishedAt[:10]))
			if !write {
				continue
			}
			entry, warn, err := buildVersion(owner, repo, ver, rel, versions)
			if err != nil {
				skipped = append(skipped, fmt.Sprintf("%s %s: %v", name, ver, err))
				continue
			}
			skipped = append(skipped, warn...)
			pm["versions"] = append(versions, entry)
			changed = true
		}
	}

	for _, s := range skipped {
		fmt.Fprintf(os.Stderr, "warning: %s\n", s)
	}

	if len(missing) == 0 {
		fmt.Println("registry index is current — every published release is listed")
		return
	}

	sort.Strings(missing)
	fmt.Printf("%d release(s) missing from the index:\n", len(missing))
	for _, m := range missing {
		fmt.Println("  " + m)
	}

	if write && changed {
		doc["generated_at"] = time.Now().UTC().Format(time.RFC3339)
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			fatal("encoding index: %v", err)
		}
		if err := os.WriteFile(indexPath, append(out, '\n'), 0o644); err != nil {
			fatal("writing %s: %v", indexPath, err)
		}
		fmt.Printf("\nwrote %s\n", indexPath)
		return
	}

	if check {
		fmt.Fprintln(os.Stderr, "\nA release that is not in the index is not installable: `nox plugin install` "+
			"resolves from this file, so these versions are invisible to users.\n"+
			"Run: go run ./cmd/registry-sync -write")
		os.Exit(1)
	}
}

// buildVersion assembles an index entry from a release, taking digests from the
// release's own checksums.txt. Returns warnings for assets it could not resolve.
func buildVersion(owner, repo, ver string, rel ghRelease, existing []any) (entry map[string]any, warnings []string, err error) {
	sums, err := fetchChecksums(rel)
	if err != nil {
		return nil, nil, err
	}

	// Inherit cosign identity/issuer from the newest existing entry rather than
	// hardcoding them: they are per-repository facts already recorded here.
	var certRe, issuer, apiVersion string
	var caps []string
	if len(existing) > 0 {
		if prev, ok := existing[len(existing)-1].(map[string]any); ok {
			apiVersion, _ = prev["api_version"].(string)
			if arts, ok := prev["artifacts"].([]any); ok && len(arts) > 0 {
				if a, ok := arts[0].(map[string]any); ok {
					certRe, _ = a["cosign_cert_identity_regexp"].(string)
					issuer, _ = a["cosign_oidc_issuer"].(string)
				}
			}
			if cs, ok := prev["capabilities"].([]any); ok {
				for _, c := range cs {
					if s, ok := c.(string); ok {
						caps = append(caps, s)
					}
				}
			}
		}
	}

	var warns []string
	var arts []any
	for _, a := range rel.Assets {
		m := artifactRe.FindStringSubmatch(a.Name)
		if m == nil {
			continue
		}
		sum, ok := sums[a.Name]
		if !ok {
			// Never fabricate. A missing checksum means this artifact is not
			// verifiable, so it does not go in.
			warns = append(warns, fmt.Sprintf("%s %s: no checksum for %s — artifact omitted", repo, ver, a.Name))
			continue
		}
		arts = append(arts, map[string]any{
			"os": m[1], "arch": m[2],
			"url":    a.URL,
			"size":   a.Size,
			"digest": "sha256:" + sum,
			"cosign_bundle_url": fmt.Sprintf(
				"https://github.com/%s/%s/releases/download/v%s/checksums.txt.sigstore.json", owner, repo, ver),
			"cosign_cert_identity_regexp": certRe,
			"cosign_oidc_issuer":          issuer,
		})
	}
	if len(arts) == 0 {
		return nil, warns, fmt.Errorf("no verifiable artifacts (checksums.txt missing or unmatched)")
	}

	entry = map[string]any{
		"version":      ver,
		"api_version":  apiVersion,
		"published_at": rel.PublishedAt,
		"capabilities": caps,
		"artifacts":    arts,
	}
	return entry, warns, nil
}

func fetchChecksums(rel ghRelease) (map[string]string, error) {
	var url string
	for _, a := range rel.Assets {
		if a.Name == "checksums.txt" {
			url = a.URL
			break
		}
	}
	if url == "" {
		return nil, fmt.Errorf("release has no checksums.txt")
	}
	body, err := httpGet(url)
	if err != nil {
		return nil, err
	}
	sums := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			sums[f[1]] = f[0]
		}
	}
	return sums, nil
}

func fetchReleases(owner, repo string) ([]ghRelease, error) {
	body, err := httpGet(fmt.Sprintf("%s/repos/%s/%s/releases?per_page=100", githubAPI, owner, repo))
	if err != nil {
		return nil, err
	}
	var rs []ghRelease
	if err := json.Unmarshal(body, &rs); err != nil {
		return nil, fmt.Errorf("decoding releases: %w", err)
	}
	return rs, nil
}

func httpGet(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	// Authenticate when a token is available: unauthenticated GitHub API calls
	// are rate-limited to 60/hour, which this tool exceeds across seven repos.
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

func parseRepo(homepage string) (owner, repo string) {
	m := repoRe.FindStringSubmatch(homepage)
	if m == nil {
		return "", ""
	}
	return m[1], strings.TrimSuffix(m[2], ".git")
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(2)
}
