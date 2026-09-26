package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Base images are dependencies too, and the one kind the currency pass could
// not see. Dependabot kept nox's Dockerfile current in two ways: refreshing a
// tag's digest when the image was rebuilt under the same tag (distroless and
// golang, several times a month), and moving the tag itself within its line
// (golang 1.26-alpine -> 1.27-alpine). Both are here.
//
// The registry is asked over the OCI distribution API, which Docker Hub,
// gcr.io, ghcr.io and every conforming registry serve: a manifest HEAD answers
// a tag's current digest, and /tags/list answers what tags exist. Anonymous
// pulls still need a bearer token from the realm the registry names in its
// 401 challenge, so that exchange is done too.

// baseImageRef is one `FROM` image in a Dockerfile.
type baseImageRef struct {
	image  string // as written, without tag or digest: golang, gcr.io/distroless/static-debian12
	tag    string // "" when the image is pinned by digest alone
	digest string // "" when not pinned by digest
}

// fromImage matches a FROM line's image reference, after any --platform flag.
var fromImage = regexp.MustCompile(`(?im)^[ \t]*FROM[ \t]+(?:--platform=\S+[ \t]+)?(\S+)`)

// baseImageRefs lists the registry images a Dockerfile builds FROM. A stage
// reference (FROM builder), the empty image (scratch) and an ARG-substituted
// name are skipped: none of them is something a registry can be asked about.
func baseImageRefs(dockerfile string) []baseImageRef {
	stages := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?im)^[ \t]*FROM[ \t]+.*[ \t]AS[ \t]+(\S+)`).FindAllStringSubmatch(dockerfile, -1) {
		stages[strings.ToLower(m[1])] = true
	}
	var refs []baseImageRef
	for _, m := range fromImage.FindAllStringSubmatch(dockerfile, -1) {
		ref := m[1]
		if strings.Contains(ref, "$") || strings.EqualFold(ref, "scratch") || stages[strings.ToLower(ref)] {
			continue
		}
		var r baseImageRef
		if at := strings.Index(ref, "@"); at >= 0 {
			r.digest = ref[at+1:]
			ref = ref[:at]
		}
		// A tag follows the last colon, unless that colon belongs to a
		// registry port (localhost:5000/tool).
		if c := strings.LastIndex(ref, ":"); c > strings.LastIndex(ref, "/") {
			r.tag = ref[c+1:]
			ref = ref[:c]
		}
		r.image = ref
		refs = append(refs, r)
	}
	return refs
}

// imageLocation splits an image name into its registry host and repository,
// applying Docker Hub's defaults: no host means docker.io, and a single-part
// name lives under library/.
func imageLocation(image string) (host, repo string) {
	first, rest, found := strings.Cut(image, "/")
	if found && (strings.ContainsAny(first, ".:") || first == "localhost") {
		return first, rest
	}
	if !strings.Contains(image, "/") {
		return "docker.io", "library/" + image
	}
	return "docker.io", image
}

// imageRegistry asks registries about images. baseFor maps a registry host to
// the URL its API is served from, and is replaced in tests.
type imageRegistry struct {
	client  *http.Client
	baseFor func(host string) string
}

func newImageRegistry() *imageRegistry {
	return &imageRegistry{
		client: &http.Client{Timeout: 30 * time.Second},
		baseFor: func(host string) string {
			if host == "docker.io" {
				return "https://registry-1.docker.io"
			}
			return "https://" + host
		},
	}
}

// manifestAccept asks for the multi-platform index first: its digest is the one
// a Dockerfile pins, so a build on any architecture resolves the same image.
const manifestAccept = "application/vnd.oci.image.index.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.docker.distribution.manifest.v2+json"

// digest returns the current digest a tag points at.
func (r *imageRegistry) digest(image, tag string) (string, error) {
	host, repo := imageLocation(image)
	resp, err := r.do(http.MethodHead, r.baseFor(host)+"/v2/"+repo+"/manifests/"+tag, manifestAccept)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck // HEAD body is empty
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s:%s: registry answered %s", image, tag, resp.Status)
	}
	d := resp.Header.Get("Docker-Content-Digest")
	if !strings.HasPrefix(d, "sha256:") {
		return "", fmt.Errorf("%s:%s: registry returned no digest", image, tag)
	}
	return d, nil
}

// maxTagPages bounds how far a tag listing is followed. Docker Hub's golang
// repository has thousands of tags; at 1000 a page this is ample, and a
// registry that never stops paginating cannot stall the pass.
const maxTagPages = 30

// tags lists the tags a repository has, following the registry's pagination.
func (r *imageRegistry) tags(image string) ([]string, error) {
	host, repo := imageLocation(image)
	base := r.baseFor(host)
	next := base + "/v2/" + repo + "/tags/list?n=1000"
	var all []string
	for page := 0; next != "" && page < maxTagPages; page++ {
		resp, err := r.do(http.MethodGet, next, "application/json")
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: tag list answered %s", image, resp.Status)
		}
		var doc struct {
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, fmt.Errorf("%s: tag list: %w", image, err)
		}
		all = append(all, doc.Tags...)
		next = nextPage(base, resp.Header.Get("Link"))
	}
	return all, nil
}

// nextPage reads the rel="next" target from a Link header, resolved against
// the registry base.
func nextPage(base, link string) string {
	m := regexp.MustCompile(`<([^>]+)>;\s*rel="next"`).FindStringSubmatch(link)
	if m == nil {
		return ""
	}
	if strings.HasPrefix(m[1], "http") {
		return m[1]
	}
	return base + m[1]
}

// do sends one request, answering a bearer challenge once if the registry
// issues one.
func (r *imageRegistry) do(method, target, accept string) (*http.Response, error) {
	send := func(token string) (*http.Response, error) {
		req, err := http.NewRequest(method, target, http.NoBody)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", accept)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		return r.client.Do(req)
	}
	resp, err := send("")
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	_ = resp.Body.Close()
	token, err := r.token(challenge)
	if err != nil {
		return nil, err
	}
	return send(token)
}

var challengeParam = regexp.MustCompile(`(\w+)="([^"]*)"`)

// token fetches an anonymous pull token from the realm a Bearer challenge
// names.
func (r *imageRegistry) token(challenge string) (string, error) {
	if !strings.HasPrefix(strings.ToLower(challenge), "bearer ") {
		return "", fmt.Errorf("registry requires authentication nox cannot provide (%q)", challenge)
	}
	params := map[string]string{}
	for _, m := range challengeParam.FindAllStringSubmatch(challenge, -1) {
		params[m[1]] = m[2]
	}
	if params["realm"] == "" {
		return "", fmt.Errorf("bearer challenge names no realm")
	}
	q := url.Values{}
	for _, k := range []string{"service", "scope"} {
		if params[k] != "" {
			q.Set(k, params[k])
		}
	}
	resp, err := r.client.Get(params["realm"] + "?" + q.Encode())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close on read body
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint answered %s", resp.Status)
	}
	var doc struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return "", err
	}
	if doc.Token != "" {
		return doc.Token, nil
	}
	return doc.AccessToken, nil
}

// numericTag splits a tag like 1.27-alpine into its version components and
// the suffix that says which variant it is.
var numericTag = regexp.MustCompile(`^(\d+(?:\.\d+)*)(-[A-Za-z][A-Za-z0-9.-]*)?$`)

// newerTag returns the newest tag of the same shape as current — the same
// number of version components and the same variant suffix — or "" if none is
// newer. A move to a new major is returned only with includeMajor; otherwise
// majorHeld reports that one was available.
//
// "Same shape" is what keeps this honest: 1.27-alpine may move to 1.28-alpine,
// but not to 1.28.1-alpine (a different granularity, which would stop the tag
// from tracking patch releases), 1.28-bookworm (a different base) or a
// prerelease like 1.29rc1-alpine, which does not match the pattern at all.
func newerTag(current string, tags []string, includeMajor bool) (tag string, majorHeld bool) {
	cm := numericTag.FindStringSubmatch(current)
	if cm == nil {
		return "", false
	}
	cparts := strings.Split(cm[1], ".")
	best, bestParts := "", cparts
	for _, t := range tags {
		m := numericTag.FindStringSubmatch(t)
		if len(m) < 3 || m[2] != cm[2] {
			continue
		}
		parts := strings.Split(m[1], ".")
		if len(parts) != len(cparts) || !partsLess(bestParts, parts) {
			continue
		}
		if parts[0] != cparts[0] && !includeMajor {
			majorHeld = true
			continue
		}
		best, bestParts = t, parts
	}
	return best, majorHeld
}

// partsLess compares dotted numeric version components.
func partsLess(a, b []string) bool {
	for i := range a {
		x, _ := strconv.Atoi(a[i])
		y, _ := strconv.Atoi(b[i])
		if x != y {
			return x < y
		}
	}
	return false
}

// isDockerfile names the files the base-image pass reads in a directory.
func isDockerfile(name string) bool {
	switch {
	case name == "Dockerfile", name == "Containerfile":
		return true
	case strings.HasPrefix(name, "Dockerfile.") && !strings.HasSuffix(name, ".tmpl"):
		return true
	case strings.HasSuffix(name, ".Dockerfile"):
		return true
	}
	return false
}

// planImageCurrency plans base-image upgrades for the Dockerfiles directly in
// dir. Each action carries the full old and new reference, so applying it is a
// textual swap on the FROM line and nothing else in the file moves.
func planImageCurrency(dir string, includeMajor bool, reg *imageRegistry) (plan upgradePlan, degraded []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return plan, []string{fmt.Sprintf("could not read %s: %v", dir, err)}
	}
	for _, e := range entries {
		if e.IsDir() || !isDockerfile(e.Name()) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			degraded = append(degraded, fmt.Sprintf("could not read %s: %v", e.Name(), err))
			continue
		}
		for _, ref := range baseImageRefs(string(raw)) {
			if ref.tag == "" {
				// Pinned by digest alone: there is no tag to follow, so there
				// is no "newer" to find.
				continue
			}
			action, held, err := planOneImage(ref, includeMajor, reg)
			if err != nil {
				degraded = append(degraded, fmt.Sprintf("could not check base image %s:%s in %s: %v", ref.image, ref.tag, e.Name(), err))
				continue
			}
			if held {
				plan.majorSkipped++
			}
			if action != nil {
				action.manifest = e.Name()
				plan.actions = append(plan.actions, *action)
			}
		}
	}
	return plan, degraded
}

// planOneImage decides what one FROM reference should become.
func planOneImage(ref baseImageRef, includeMajor bool, reg *imageRegistry) (*upgradeAction, bool, error) {
	newTag := ref.tag
	var majorHeld bool
	if numericTag.MatchString(ref.tag) {
		tags, err := reg.tags(ref.image)
		if err != nil {
			return nil, false, err
		}
		var t string
		t, majorHeld = newerTag(ref.tag, tags, includeMajor)
		if t != "" {
			newTag = t
		}
	}
	from := ref.tag
	to := newTag
	if ref.digest != "" {
		d, err := reg.digest(ref.image, newTag)
		if err != nil {
			return nil, false, err
		}
		from += "@" + ref.digest
		to += "@" + d
	}
	if from == to {
		return nil, majorHeld, nil
	}
	return &upgradeAction{
		ruleID:    "OUTDATED",
		pkg:       ref.image,
		fromVer:   from,
		toVersion: to,
		ecosystem: "docker",
		action:    "FROM",
	}, majorHeld, nil
}

// applyImageUpgrade swaps the old reference for the new one in the Dockerfile
// the action came from. The whole old reference must be present, so a file
// that changed since planning is an error rather than a partial rewrite.
func applyImageUpgrade(dir string, a upgradeAction) error {
	path := filepath.Join(dir, filepath.Base(a.manifest))
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	oldRef := a.pkg + ":" + a.fromVer
	newRef := a.pkg + ":" + a.toVersion
	if !strings.Contains(string(raw), oldRef) {
		return fmt.Errorf("%s no longer contains %s", filepath.Base(path), oldRef)
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.ReplaceAll(string(raw), oldRef, newRef)), info.Mode().Perm())
}
