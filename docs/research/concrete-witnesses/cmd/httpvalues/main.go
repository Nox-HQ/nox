// Command httpvalues is the CSP/ETag case generalised: for every vendor rule,
// it writes RFC-defined non-credential HTTP values beside that vendor's name,
// in the shapes such values actually take, and reports every secret finding
// that lands on one. Each finding is replayed alone, with every scope.
//
//	go run ./cmd/httpvalues -nox <nox> -rules <rule dump> -out <dir>
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nox-hq/nox/docs/research/concrete-witnesses/refs"
)

type value struct {
	Kind  string // etag-md5 | etag-sha1 | etag-weak-b64 | csp-sha256 | traceparent | uuid
	Field string // the quoted/unquoted text as written
	Check func(string) bool
}

type shape struct {
	Name, Ext string
	// Render returns the file and the field text, which must occur in it once.
	Render func(kw string, v value) string
	Kinds  []string
}

type witness struct {
	Rule, Keyword, Shape, Kind, File, Content string
	Rules                                     []string
	Replayed                                  bool
}

func main() {
	noxBin := flag.String("nox", "", "built nox binary")
	ruleDump := flag.String("rules", "", "rule dump")
	out := flag.String("out", "", "output directory")
	flag.Parse()
	r := rand.New(rand.NewSource(20261004))

	b, err := os.ReadFile(*ruleDump)
	must(err)
	var rules []struct {
		ID                     string
		Keywords               []string `json:"keywords"`
		RequireContextKeywords []string `json:"require_context_keywords"`
		OptIn                  bool     `json:"opt_in"`
	}
	must(json.Unmarshal(b, &rules))

	// One vendor name per rule: the proximity keyword when the rule has one,
	// else its first file keyword. Distinct names only; a name shared by
	// several rules is one experiment.
	kwRules := map[string][]string{}
	for _, ru := range rules {
		if ru.OptIn {
			continue
		}
		kw := ""
		if len(ru.RequireContextKeywords) > 0 {
			kw = ru.RequireContextKeywords[0]
		} else if len(ru.Keywords) > 0 {
			kw = ru.Keywords[0]
		}
		if len(kw) < 3 || strings.ContainsAny(kw, " \"'\\\n") {
			continue
		}
		kwRules[kw] = append(kwRules[kw], ru.ID)
	}
	var kws []string
	for k := range kwRules {
		kws = append(kws, k)
	}
	sort.Strings(kws)

	mk := func(kind string) value {
		switch kind {
		case "etag-md5":
			return value{kind, `"` + randHex(r, 32) + `"`, refs.EntityTag}
		case "etag-sha1":
			return value{kind, `"` + randHex(r, 40) + `"`, refs.EntityTag}
		case "etag-weak-b64":
			buf := make([]byte, 20)
			r.Read(buf)
			return value{kind, `W/"` + base64.RawURLEncoding.EncodeToString(buf) + `"`, refs.EntityTag}
		case "csp-sha256":
			h := sha256.Sum256([]byte(randHex(r, 16)))
			return value{kind, `'sha256-` + base64.StdEncoding.EncodeToString(h[:]) + `'`, refs.CSPHashSource}
		case "traceparent":
			return value{kind, "00-" + randHex(r, 32) + "-" + randHex(r, 16) + "-01", refs.Traceparent}
		case "uuid":
			u := randHex(r, 32)
			return value{kind, u[:8] + "-" + u[8:12] + "-4" + u[13:16] + "-a" + u[17:20] + "-" + u[20:], refs.UUID}
		}
		panic(kind)
	}
	etags := []string{"etag-md5", "etag-sha1", "etag-weak-b64"}
	shapes := []shape{
		// The v1.35.0 shape: a CSP naming the vendor, an ETag below it.
		{"http-dump", "txt", func(kw string, v value) string {
			return "HTTP/2 200\ncontent-security-policy: script-src 'self' https://cdn." + kw + ".com; connect-src https://api." + kw + ".com\ncache-control: max-age=60\netag: " + v.Field + "\n"
		}, etags},
		{"json-fixture", "json", func(kw string, v value) string {
			return `{"provider": "` + kw + `", "etag": ` + jsonQuote(v.Field) + "}\n"
		}, etags},
		{"js-conditional-get", "js", func(kw string, v value) string {
			return `await fetch("https://api.` + kw + `.com/v1/items", { headers: { "If-None-Match": ` + jsonQuote(v.Field) + ` } });` + "\n"
		}, etags},
		{"csp-hash", "conf", func(kw string, v value) string {
			return `add_header Content-Security-Policy "script-src ` + v.Field + ` https://js.` + kw + `.com";` + "\n"
		}, []string{"csp-sha256"}},
		{"trace-headers", "http", func(kw string, v value) string {
			return "POST https://hooks." + kw + ".com/events\ntraceparent: " + v.Field + "\n"
		}, []string{"traceparent"}},
		{"request-id-log", "log", func(kw string, v value) string {
			return "level=info msg=\"" + kw + " webhook delivered\" request_id=" + v.Field + "\n"
		}, []string{"uuid"}},
	}

	type cand struct {
		kw, shape, kind, file, content, field string
		line, col                             int
	}
	var cands []cand
	dir := filepath.Join(*out, "search", "t")
	must(os.MkdirAll(dir, 0o755))
	for _, kw := range kws {
		for _, sh := range shapes {
			for _, k := range sh.Kinds {
				v := mk(k)
				if !v.Check(v.Field) {
					log.Fatalf("generated %s %q fails its own reference", k, v.Field)
				}
				c := sh.Render(kw, v)
				// Locate the value's content, not its delimiters: a JSON host
				// escapes the quotes of an entity-tag.
				core := strings.Trim(strings.TrimPrefix(v.Field, "W/"), `"'`)
				i := strings.Index(c, core)
				line := 1 + strings.Count(c[:i], "\n")
				col := i - (strings.LastIndex(c[:i], "\n") + 1) + 1
				f := fmt.Sprintf("h%05d.%s", len(cands), sh.Ext)
				must(os.WriteFile(filepath.Join(dir, f), []byte(c), 0o644))
				cands = append(cands, cand{kw, sh.Name, k, f, c, core, line, col})
			}
		}
	}
	hits := scan(*noxBin, dir, filepath.Join(*out, "search", "o"), "--only", "secrets")

	var ws []witness
	for _, c := range cands {
		ids := onField(hits[c.file], c.line, c.col, c.col+len(c.field))
		if len(ids) == 0 {
			continue
		}
		w := witness{Keyword: c.kw, Shape: c.shape, Kind: c.kind, File: c.file, Content: c.content, Rules: ids}
		rd := filepath.Join(*out, "replay", strings.TrimSuffix(c.file, filepath.Ext(c.file)))
		must(os.MkdirAll(filepath.Join(rd, "t"), 0o755))
		must(os.WriteFile(filepath.Join(rd, "t", c.file), []byte(c.content), 0o644))
		again := onField(scan(*noxBin, filepath.Join(rd, "t"), filepath.Join(rd, "o"))[c.file], c.line, c.col, c.col+len(c.field))
		w.Replayed = len(again) > 0
		ws = append(ws, w)
	}
	j, _ := json.MarshalIndent(map[string]any{"vendor_names": len(kws), "files": len(cands), "witnesses": ws}, "", " ")
	must(os.WriteFile(filepath.Join(*out, "httpvalues.json"), j, 0o644))
	fmt.Printf("vendor names=%d files=%d witnesses=%d\n", len(kws), len(cands), len(ws))
	for _, w := range ws {
		fmt.Printf("%-24s %-20s %-14s %v replayed=%v rules-for-name=%v\n", w.Keyword, w.Shape, w.Kind, w.Rules, w.Replayed, kwRules[w.Keyword])
	}
}

type finding struct {
	RuleID   string
	Location struct {
		FilePath               string
		StartLine, EndLine     int
		StartColumn, EndColumn int
	}
}

func onField(fs []finding, line, start, end int) []string {
	var ids []string
	for _, f := range fs {
		l := f.Location
		if l.StartLine <= line && l.EndLine >= line && (l.StartLine < line || l.StartColumn < end) && (l.EndLine > line || l.EndColumn > start) {
			ids = append(ids, f.RuleID)
		}
	}
	return ids
}

func scan(bin, target, outDir string, extra ...string) map[string][]finding {
	must(os.MkdirAll(outDir, 0o755))
	_ = exec.Command(bin, append([]string{"scan", target, "--offline", "-output", outDir, "-q"}, extra...)...).Run()
	b, err := os.ReadFile(filepath.Join(outDir, "findings.json"))
	must(err)
	var doc struct{ Findings []finding }
	must(json.Unmarshal(b, &doc))
	m := map[string][]finding{}
	for _, f := range doc.Findings {
		m[filepath.Base(f.Location.FilePath)] = append(m[filepath.Base(f.Location.FilePath)], f)
	}
	return m
}

func randHex(r *rand.Rand, n int) string {
	b := make([]byte, (n+1)/2)
	r.Read(b)
	return hex.EncodeToString(b)[:n]
}

func jsonQuote(s string) string { b, _ := json.Marshal(s); return string(b) }

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
