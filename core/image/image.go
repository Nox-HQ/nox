// Package image reads what a container image has installed, from the image's
// own files, without running it (nox-hq/nox#1013).
//
// An image is fetched by digest over the OCI distribution API, every blob is
// checked against its digest and cached by it, and the layers are applied in
// order with whiteouts. Only the files that list installed software are kept:
// os-release, Alpine's apk database, Debian's dpkg status (and distroless
// status.d), the Go toolchain's VERSION, and Go executables' build info.
// Nothing in the image is executed, nothing is written outside the cache, and
// the answer for a digest never changes, so a scan that reads it stays
// deterministic.
package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Ref is where an image lives.
type Ref struct {
	Registry   string // host[:port]; Docker Hub is registry-1.docker.io
	Repository string // library/golang
}

// ParseRef reads an image name the way docker does: the first component is a
// registry when it has a dot or a port or is localhost; Docker Hub's official
// images live under library/. A tag, if present, is dropped: nox reads by
// digest only.
func ParseRef(name string) Ref {
	name, _, _ = strings.Cut(name, "@")
	if slash := strings.LastIndex(name, "/"); strings.LastIndex(name, ":") > slash {
		name = name[:strings.LastIndex(name, ":")]
	}
	first, rest, hasSlash := strings.Cut(name, "/")
	reg := "registry-1.docker.io"
	if hasSlash && (strings.ContainsAny(first, ".:") || first == "localhost") {
		reg, name = first, rest
	}
	if reg == "docker.io" || reg == "index.docker.io" {
		reg = "registry-1.docker.io"
	}
	if reg == "registry-1.docker.io" && !strings.Contains(name, "/") {
		name = "library/" + name
	}
	return Ref{Registry: reg, Repository: name}
}

// Package is one piece of installed software found in an image.
type Package struct {
	Name      string
	Version   string
	Ecosystem string // "alpine:v3.22", "debian:12", "go"
	Path      string // the file inside the image that lists it
}

// Contents is what an image has installed.
type Contents struct {
	// Distro is the distribution's ecosystem ("alpine:v3.22"), or "" when
	// the image has no os-release nox can read.
	Distro   string
	Packages []Package
	// Notes say what was found but could not be listed (a distribution with
	// no version, an unread package database).
	Notes []string
}

// Client reads images from registries.
type Client struct {
	HTTP *http.Client
	// CacheDir holds blobs by digest. Required.
	CacheDir string
	// Offline reads from the cache only.
	Offline bool
	// MaxBytes bounds the compressed bytes of one image's layers; 0 is 2 GiB.
	MaxBytes int64
	// OS and Arch choose from a multi-platform index; "" is linux/amd64.
	OS, Arch string

	registryOverride string // tests: a base URL that replaces https://<registry>
	mu               sync.Mutex
	tokens           map[string]string
	contacted        map[string]struct{}
}

// Contacted returns every host this client sent a request to, sorted: the
// registries, the token services their challenges named, and the hosts their
// blob requests redirected to. A read the cache answered contacts none.
func (c *Client) Contacted() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	hosts := make([]string, 0, len(c.contacted))
	for h := range c.contacted {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// do sends req and records where it went: the host asked, and the host that
// answered when the request was redirected.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	c.noteContact(req.URL.Host)
	resp, err := hc.Do(req)
	if err == nil && resp.Request != nil {
		c.noteContact(resp.Request.URL.Host)
	}
	return resp, err
}

func (c *Client) noteContact(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.contacted == nil {
		c.contacted = map[string]struct{}{}
	}
	c.contacted[host] = struct{}{}
}

const (
	defaultMaxBytes = 2 << 30
	maxListingBytes = 16 << 20 // one package database file
	// maxRPMDBBytes bounds rpm's sqlite database, which carries every
	// package's file list and runs to tens of megabytes on a full EL image.
	maxRPMDBBytes = 256 << 20
)

// Contents fetches the image name pins by digest and reads what it has
// installed.
func (c *Client) Contents(ctx context.Context, name, digest string) (Contents, error) {
	if !strings.HasPrefix(digest, "sha256:") {
		return Contents{}, fmt.Errorf("%s: only sha256 digests are read", digest)
	}
	ref := ParseRef(name)
	layers, err := c.layers(ctx, ref, digest)
	if err != nil {
		return Contents{}, err
	}
	var total int64
	for _, l := range layers {
		total += l.Size
	}
	budget := c.MaxBytes
	if budget <= 0 {
		budget = defaultMaxBytes
	}
	if total > budget {
		return Contents{}, fmt.Errorf("%s@%s: layers total %d bytes, over the %d-byte budget", name, digest, total, budget)
	}
	files := map[string][]byte{}
	// Layers are compressed, and a small one can expand to almost anything;
	// what is read after decompression is bounded too.
	unpacked := &budgetReader{left: 4 * budget, what: fmt.Sprintf("%s@%s unpacked", name, digest)}
	for _, l := range layers {
		if err := c.applyLayer(ctx, ref, l, files, unpacked); err != nil {
			return Contents{}, err
		}
	}
	return readContents(files), nil
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform,omitempty"`
}

type manifestDoc struct {
	MediaType string       `json:"mediaType"`
	Manifests []descriptor `json:"manifests"`
	Layers    []descriptor `json:"layers"`
}

// layers resolves digest (an index or a manifest) to the chosen platform's
// layer descriptors, in order.
func (c *Client) layers(ctx context.Context, ref Ref, digest string) ([]descriptor, error) {
	for range 2 { // an index, then the manifest it points to
		body, err := c.blob(ctx, ref, "manifests", digest)
		if err != nil {
			return nil, err
		}
		var m manifestDoc
		if err := json.Unmarshal(body, &m); err != nil {
			return nil, fmt.Errorf("manifest %s: %w", digest, err)
		}
		if len(m.Manifests) == 0 {
			return m.Layers, nil
		}
		next := c.choosePlatform(m.Manifests)
		if next == "" {
			return nil, fmt.Errorf("index %s has no %s/%s image", digest, c.os(), c.arch())
		}
		digest = next
	}
	return nil, fmt.Errorf("manifest %s: an index pointed at another index", digest)
}

func (c *Client) os() string   { return orDefault(c.OS, "linux") }
func (c *Client) arch() string { return orDefault(c.Arch, "amd64") }

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func (c *Client) choosePlatform(ms []descriptor) string {
	for _, m := range ms {
		if m.Platform != nil && m.Platform.OS == c.os() && m.Platform.Architecture == c.arch() {
			return m.Digest
		}
	}
	return ""
}

var layerWanted = regexp.MustCompile(`^(etc/os-release|usr/lib/os-release|lib/apk/db/installed|var/lib/dpkg/status|var/lib/dpkg/status\.d/[^/]+|usr/local/go/VERSION|var/lib/rpm/rpmdb\.sqlite)$`)

// rpmMarkers are kept for their presence and size only: rpm's Berkeley DB
// (EL8 and earlier), which nox does not read, and a write-ahead log, whose
// frames would be rows the main database file does not yet hold.
var rpmMarkers = map[string]bool{"var/lib/rpm/Packages": true, "var/lib/rpm/rpmdb.sqlite-wal": true}

// markerTag starts the value kept for a marker file: its size, not its bytes.
const markerTag = "\x00marker\x00"

// applyLayer applies one layer's whiteouts to files, then its additions, keeping
// only the paths that list installed software.
func (c *Client) applyLayer(ctx context.Context, ref Ref, l descriptor, files map[string][]byte, unpacked *budgetReader) error {
	body, err := c.blobReader(ctx, ref, l.Digest)
	if err != nil {
		return err
	}
	defer func() { _ = body.Close() }()
	var r io.Reader = body
	switch {
	case strings.HasSuffix(l.MediaType, "+gzip"), strings.HasSuffix(l.MediaType, ".tar.gzip"), strings.Contains(l.MediaType, "rootfs.diff.tar.gzip"):
		gz, err := gzip.NewReader(body)
		if err != nil {
			return fmt.Errorf("layer %s: %w", l.Digest, err)
		}
		defer func() { _ = gz.Close() }()
		r = gz
	case strings.HasSuffix(l.MediaType, ".tar"):
	default:
		return fmt.Errorf("layer %s: %s compression is not read", l.Digest, l.MediaType)
	}

	var deleted, opaque, replaced []string
	added := map[string][]byte{}
	unpacked.r = r
	tr := tar.NewReader(unpacked)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("layer %s: %w", l.Digest, err)
		}
		name := path.Clean(strings.TrimPrefix(strings.TrimPrefix(hdr.Name, "./"), "/"))
		dir, base := path.Split(name)
		switch {
		case base == ".wh..wh..opq":
			opaque = append(opaque, strings.TrimSuffix(dir, "/"))
		case strings.HasPrefix(base, ".wh."):
			deleted = append(deleted, dir+strings.TrimPrefix(base, ".wh."))
		case hdr.Typeflag == tar.TypeReg && rpmMarkers[name]:
			added[name] = []byte(markerTag + strconv.FormatInt(hdr.Size, 10))
		case hdr.Typeflag == tar.TypeReg && layerWanted.MatchString(name):
			limit := int64(maxListingBytes)
			if name == "var/lib/rpm/rpmdb.sqlite" {
				limit = maxRPMDBBytes
			}
			if hdr.Size > limit {
				return fmt.Errorf("layer %s: %s is %d bytes, over the %d-byte limit", l.Digest, name, hdr.Size, limit)
			}
			b, err := io.ReadAll(io.LimitReader(tr, limit))
			if err != nil {
				return fmt.Errorf("layer %s: %w", l.Digest, err)
			}
			added[name] = b
		case hdr.Typeflag == tar.TypeReg && hdr.Size >= minExecutableSize && (hdr.Mode&0o111 != 0 || sharedObject.MatchString(base)):
			if info := probeExecutable(tr, name); !info.empty() {
				added[name] = encodeExecutable(info)
			} else {
				replaced = append(replaced, name)
			}
		default:
			// Anything else at a path replaces what a lower layer put there:
			// a Go binary overwritten by a shell script is not in the image.
			replaced = append(replaced, name)
		}
	}
	for p := range files {
		for _, d := range opaque {
			if strings.HasPrefix(p, d+"/") {
				delete(files, p)
			}
		}
		for _, d := range deleted {
			if p == d || strings.HasPrefix(p, d+"/") {
				delete(files, p)
			}
		}
	}
	for _, p := range replaced {
		delete(files, p)
	}
	for p, b := range added {
		files[p] = b
	}
	return nil
}

// budgetReader fails once more than left bytes have been read through it,
// across every layer it is handed.
type budgetReader struct {
	r    io.Reader
	left int64
	what string
}

func (b *budgetReader) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, fmt.Errorf("%s: over the byte budget", b.what)
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.r.Read(p)
	b.left -= int64(n)
	return n, err
}

// blob reads a manifest or blob in full, checked against its digest.
func (c *Client) blob(ctx context.Context, ref Ref, kind, digest string) ([]byte, error) {
	rc, err := c.fetch(ctx, ref, kind, digest)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	return io.ReadAll(rc)
}

func (c *Client) blobReader(ctx context.Context, ref Ref, digest string) (io.ReadCloser, error) {
	return c.fetch(ctx, ref, "blobs", digest)
}

// fetch returns the content for digest from the cache, or fetches, verifies
// and caches it first. What it returns has been checked against digest.
func (c *Client) fetch(ctx context.Context, ref Ref, kind, digest string) (io.ReadCloser, error) {
	if c.CacheDir == "" {
		return nil, errors.New("image: no cache directory")
	}
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	if len(hexDigest) != 64 || strings.Trim(hexDigest, "0123456789abcdef") != "" {
		return nil, fmt.Errorf("%s is not a sha256 digest", digest)
	}
	cached := filepath.Join(c.CacheDir, "blobs", "sha256", hexDigest)
	if f, err := os.Open(cached); err == nil { //nolint:gosec // a path built from a verified hex digest
		return f, nil
	}
	if c.Offline {
		return nil, fmt.Errorf("%s is not in the image cache, and the scan is offline", digest)
	}
	resp, err := c.get(ctx, ref, kind, digest)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := os.MkdirAll(filepath.Dir(cached), 0o750); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(cached), "partial-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	h := sha256.New()
	limit := c.MaxBytes
	if limit <= 0 {
		limit = defaultMaxBytes
	}
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, limit+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", digest, err)
	}
	if n > limit {
		return nil, fmt.Errorf("%s: over the %d-byte budget", digest, limit)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != hexDigest {
		return nil, fmt.Errorf("%s: content does not match its digest (got sha256:%s)", digest, got)
	}
	if err := os.Rename(tmp.Name(), cached); err != nil {
		return nil, err
	}
	return os.Open(cached) //nolint:gosec // a path built from a verified hex digest
}

var manifestAccept = strings.Join([]string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}, ", ")

// get requests a manifest or blob, answering a bearer challenge with an
// anonymous token once.
func (c *Client) get(ctx context.Context, ref Ref, kind, digest string) (*http.Response, error) {
	base := "https://" + ref.Registry
	if c.registryOverride != "" {
		base = c.registryOverride
	}
	u := fmt.Sprintf("%s/v2/%s/%s/%s", base, ref.Repository, kind, digest)
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
		if err != nil {
			return nil, err
		}
		if kind == "manifests" {
			req.Header.Set("Accept", manifestAccept)
		}
		if tok := c.token(ref); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := c.do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			challenge := resp.Header.Get("WWW-Authenticate")
			_ = resp.Body.Close()
			if err := c.authorize(ctx, ref, challenge); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("%s %s: %s", ref.Registry, digest, resp.Status)
		}
		return resp, nil
	}
	return nil, fmt.Errorf("%s: the registry refused an anonymous pull of %s; it needs credentials, which nox does not send", ref.Registry, ref.Repository)
}

func (c *Client) token(ref Ref) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tokens[ref.Registry+"/"+ref.Repository]
}

var challengeParam = regexp.MustCompile(`(\w+)="([^"]*)"`)

// authorize answers a "Bearer realm=…,service=…,scope=…" challenge with an
// anonymous token for pulling ref.
func (c *Client) authorize(ctx context.Context, ref Ref, challenge string) error {
	if !strings.HasPrefix(strings.ToLower(challenge), "bearer ") {
		return fmt.Errorf("%s asks for %q authentication, which nox does not do", ref.Registry, strings.SplitN(challenge, " ", 2)[0])
	}
	params := map[string]string{}
	for _, m := range challengeParam.FindAllStringSubmatch(challenge, -1) {
		params[m[1]] = m[2]
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || realm.Scheme == "" {
		return fmt.Errorf("%s: unreadable token realm %q", ref.Registry, params["realm"])
	}
	q := realm.Query()
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	scope := params["scope"]
	if scope == "" {
		scope = "repository:" + ref.Repository + ":pull"
	}
	q.Set("scope", scope)
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), http.NoBody)
	if err != nil {
		return err
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: anonymous token for %s: %s", ref.Registry, ref.Repository, resp.Status)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return err
	}
	t := orDefault(tok.Token, tok.AccessToken)
	if t == "" {
		return fmt.Errorf("%s: the token endpoint returned no token", ref.Registry)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tokens == nil {
		c.tokens = map[string]string{}
	}
	c.tokens[ref.Registry+"/"+ref.Repository] = t
	return nil
}

// readContents turns the kept files into packages.
func readContents(files map[string][]byte) Contents {
	var out Contents
	release := files["etc/os-release"]
	if release == nil {
		release = files["usr/lib/os-release"]
	}
	osr := parseKeyValues(release)
	switch id := osr["ID"]; id {
	case "alpine":
		if v := osr["VERSION_ID"]; v != "" {
			parts := strings.SplitN(v, ".", 3)
			if len(parts) >= 2 {
				out.Distro = "alpine:v" + parts[0] + "." + parts[1]
			}
		}
	case "debian":
		if v := osr["VERSION_ID"]; v != "" {
			out.Distro = "debian:" + v
		}
	case "almalinux", "rocky":
		// OSV publishes these per major release ("AlmaLinux:9").
		if v := osr["VERSION_ID"]; v != "" {
			major, _, _ := strings.Cut(v, ".")
			out.Distro = id + ":" + major
		}
	case "ubuntu":
		// Ubuntu publishes advisories per support stream, and os-release
		// says which applies: "24.04.3 LTS (Noble Numbat)" is the LTS
		// stream, any other release stands alone.
		if v := osr["VERSION_ID"]; v != "" {
			out.Distro = "ubuntu:" + v
			if strings.Contains(osr["VERSION"], "LTS") {
				out.Distro += ":LTS"
			}
		}
	}
	if osr["ID"] != "" && out.Distro == "" {
		out.Notes = append(out.Notes, fmt.Sprintf("%s has no release version in os-release, so its packages cannot be matched to advisories", osr["ID"]))
	}

	pkgs, notes := rpmContents(files, osr["ID"], out.Distro)
	out.Packages = append(out.Packages, pkgs...)
	out.Notes = append(out.Notes, notes...)
	if db, ok := files["lib/apk/db/installed"]; ok && out.Distro != "" {
		out.Packages = append(out.Packages, apkPackages(db, out.Distro)...)
	}
	var dpkgFiles []string
	for p := range files {
		if p == "var/lib/dpkg/status" || strings.HasPrefix(p, "var/lib/dpkg/status.d/") {
			dpkgFiles = append(dpkgFiles, p)
		}
	}
	sort.Strings(dpkgFiles)
	if out.Distro != "" {
		for _, p := range dpkgFiles {
			out.Packages = append(out.Packages, dpkgPackages(files[p], p, out.Distro)...)
		}
	}
	exe, exeNotes := executablePackages(files)
	out.Packages = append(out.Packages, exe...)
	out.Notes = append(out.Notes, exeNotes...)
	if v, ok := files["usr/local/go/VERSION"]; ok {
		first, _, _ := strings.Cut(string(v), "\n")
		if ver := strings.TrimPrefix(strings.TrimSpace(first), "go"); ver != "" && ver != first {
			out.Packages = append(out.Packages, Package{Name: "stdlib", Version: ver, Ecosystem: "go", Path: "usr/local/go/VERSION"})
		}
	}
	out.Packages = dedupe(out.Packages)
	return out
}

// apkPackages reads Alpine's installed database. OSV's Alpine advisories name
// the source package (o:), which several binary packages can share.
func apkPackages(db []byte, eco string) []Package {
	var out []Package
	for _, block := range strings.Split(string(db), "\n\n") {
		var name, version, origin string
		for _, line := range strings.Split(block, "\n") {
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			switch k {
			case "P":
				name = v
			case "V":
				version = v
			case "o":
				origin = v
			}
		}
		if origin == "" {
			origin = name
		}
		if origin != "" && version != "" {
			out = append(out, Package{Name: origin, Version: version, Ecosystem: eco, Path: "lib/apk/db/installed"})
		}
	}
	return out
}

// dpkgPackages reads a dpkg status file (or one distroless status.d entry).
// Only installed packages count; OSV's Debian advisories name the source
// package at the source version, which Source gives when it differs.
func dpkgPackages(status []byte, file, eco string) []Package {
	var out []Package
	for _, para := range strings.Split(strings.ReplaceAll(string(status), "\r\n", "\n"), "\n\n") {
		f := parseControl(para)
		if f["Package"] == "" || f["Version"] == "" {
			continue
		}
		if st := f["Status"]; st != "" && !strings.HasSuffix(st, " installed") {
			continue
		}
		name, version := f["Package"], f["Version"]
		if src := f["Source"]; src != "" {
			s, v, hasVersion := strings.Cut(src, " (")
			name = strings.TrimSpace(s)
			if hasVersion {
				version = strings.TrimSuffix(strings.TrimSpace(v), ")")
			}
		}
		out = append(out, Package{Name: name, Version: version, Ecosystem: eco, Path: file})
	}
	return out
}

// parseControl reads one deb822 paragraph, skipping continuation lines.
func parseControl(para string) map[string]string {
	f := map[string]string{}
	for _, line := range strings.Split(para, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			f[k] = strings.TrimSpace(v)
		}
	}
	return f
}

// parseKeyValues reads os-release: KEY=value, value optionally quoted.
func parseKeyValues(b []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(bytes.TrimSpace(b)), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		out[k] = strings.Trim(v, `"'`)
	}
	return out
}

func dedupe(ps []Package) []Package {
	seen := map[Package]bool{}
	var out []Package
	for _, p := range ps {
		key := Package{Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}
