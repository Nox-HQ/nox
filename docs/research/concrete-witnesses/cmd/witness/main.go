// Command witness searches for disagreement between nox and the reference
// predicates in refs/, and replays every disagreement through real nox.
//
//	go run ./cmd/witness -nox <built nox binary> -rules <rule dump json> -out <dir>
//
// actual(x) is always a nox binary scanning a file on disk: search and replay
// differ only in that search scans every candidate in one batch, with the
// secrets scope only, and replay scans each witness alone with every scope.
// The key denominator is replayed witnesses.
package main

import (
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

type candidate struct {
	Format    string `json:"format"`
	Origin    string `json:"origin"` // ref-valid | ref-mutant | detector:<rule>
	Variant   string `json:"variant"`
	Input     string `json:"input"`
	Host      string `json:"host"`
	Violation string `json:"reference_violation"` // "" = reference-valid
	File      string `json:"file"`
	startLine int
	endLine   int
	startCol  int // 1-based, single-line candidates only
	endCol    int
}

type finding struct {
	RuleID   string
	Location struct {
		FilePath               string
		StartLine, EndLine     int
		StartColumn, EndColumn int
	}
}

type outcome struct {
	candidate
	Claimed   []string `json:"claimed_rules"` // claiming rules reporting on the span
	Others    []string `json:"other_rules"`   // any other rule reporting on the span
	Direction string   `json:"direction"`     // fp | fn | claim-gap | agree
	Replayed  *bool    `json:"replayed,omitempty"`
	ReplayAll []string `json:"replay_rules,omitempty"`
}

func main() {
	noxBin := flag.String("nox", "", "built nox binary")
	ruleDump := flag.String("rules", "", "rule dump from TestDumpRuleSet")
	out := flag.String("out", "", "output directory")
	seed := flag.Int64("seed", 20261004, "RNG seed")
	flag.Parse()
	if *noxBin == "" || *ruleDump == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	patterns := loadPatterns(*ruleDump)
	r := rand.New(rand.NewSource(*seed))

	var cands []*candidate
	for _, f := range refs.Modelled {
		var inputs []refs.Named
		var origins []string
		for _, v := range f.Valid(r) {
			inputs, origins = append(inputs, v), append(origins, "ref-valid")
			for _, m := range f.Mutate(r, v.S) {
				inputs, origins = append(inputs, refs.Named{Name: v.Name + "/" + m.Name, S: m.S}), append(origins, "ref-mutant")
			}
		}
		for _, id := range f.Claims {
			for i, s := range detectorSamples(patterns[id], r) {
				inputs, origins = append(inputs, refs.Named{Name: fmt.Sprintf("path-%d", i), S: s}), append(origins, "detector:"+id)
			}
		}
		for i, in := range inputs {
			for _, h := range f.Hosts {
				if !strings.Contains(in.S, "\n") && h.Name == "raw-file" {
					continue
				}
				cands = append(cands, &candidate{Format: f.Name, Origin: origins[i], Variant: in.Name, Input: in.S, Host: h.Name, Violation: f.Check(in.S)})
			}
		}
	}

	search := filepath.Join(*out, "search")
	must(os.MkdirAll(filepath.Join(search, "t"), 0o755))
	hostOf := map[string]refs.Host{}
	for _, f := range refs.Modelled {
		for _, h := range f.Hosts {
			hostOf[f.Name+"/"+h.Name] = h
		}
	}
	for i, c := range cands {
		h := hostOf[c.Format+"/"+c.Host]
		content, off := h.Wrap(c.Input)
		c.File = fmt.Sprintf("c%05d.%s", i, h.Ext)
		c.startLine = 1 + strings.Count(content[:off], "\n")
		// Each file holds one candidate and a host header before it, so the
		// candidate runs from its first line to the end of the file.
		c.endLine = strings.Count(strings.TrimRight(content, "\n"), "\n") + 1
		lineStart := strings.LastIndex(content[:off], "\n") + 1
		c.startCol = off - lineStart + 1
		c.endCol = c.startCol + len(c.Input)
		must(os.WriteFile(filepath.Join(search, "t", c.File), []byte(content), 0o644))
	}
	byFile := scan(*noxBin, filepath.Join(search, "t"), filepath.Join(search, "o"), "--only", "secrets")

	claims := map[string]map[string]bool{}
	for _, f := range refs.Modelled {
		claims[f.Name] = map[string]bool{}
		for _, id := range f.Claims {
			claims[f.Name][id] = true
		}
	}
	var res []*outcome
	for _, c := range cands {
		o := classify(c, byFile[c.File], claims[c.Format])
		res = append(res, o)
	}

	// Replay every disagreement alone, with every scope, in a fresh tree.
	replayRoot := filepath.Join(*out, "replay")
	n := 0
	for _, o := range res {
		if o.Direction == "agree" {
			continue
		}
		dir := filepath.Join(replayRoot, fmt.Sprintf("w%04d", n))
		n++
		must(os.MkdirAll(filepath.Join(dir, "t"), 0o755))
		content, _ := hostOf[o.Format+"/"+o.Host].Wrap(o.Input)
		must(os.WriteFile(filepath.Join(dir, "t", o.File), []byte(content), 0o644))
		got := scan(*noxBin, filepath.Join(dir, "t"), filepath.Join(dir, "o"))
		again := classify(&o.candidate, got[o.File], claims[o.Format])
		ok := again.Direction == o.Direction
		o.Replayed = &ok
		o.ReplayAll = append(again.Claimed, again.Others...)
	}

	b, _ := json.MarshalIndent(res, "", " ")
	must(os.WriteFile(filepath.Join(*out, "outcomes.json"), b, 0o644))
	summarise(res)
}

func classify(c *candidate, fs []finding, claim map[string]bool) *outcome {
	o := &outcome{candidate: *c}
	multi := c.startLine != c.endLine || strings.Contains(c.Input, "\n")
	for _, f := range fs {
		l := f.Location
		var overlap bool
		if multi {
			overlap = l.StartLine <= c.endLine && l.EndLine >= c.startLine
		} else {
			overlap = l.StartLine == c.startLine && l.StartColumn < c.endCol && l.EndColumn > c.startCol
		}
		if !overlap {
			continue
		}
		if claim[f.RuleID] {
			o.Claimed = appendUniq(o.Claimed, f.RuleID)
		} else {
			o.Others = appendUniq(o.Others, f.RuleID)
		}
	}
	valid := c.Violation == ""
	switch {
	case len(o.Claimed) > 0 && !valid:
		o.Direction = "fp"
	case valid && len(o.Claimed)+len(o.Others) == 0:
		o.Direction = "fn"
	case valid && len(o.Claimed) == 0:
		o.Direction = "claim-gap"
	default:
		o.Direction = "agree"
	}
	return o
}

func appendUniq(s []string, x string) []string {
	for _, y := range s {
		if y == x {
			return s
		}
	}
	return append(s, x)
}

func scan(bin, target, outDir string, extra ...string) map[string][]finding {
	must(os.MkdirAll(outDir, 0o755))
	args := append([]string{"scan", target, "--offline", "-output", outDir, "-q"}, extra...)
	cmd := exec.Command(bin, args...)
	// stderr carries only the "installed plugins did not run" notice; the
	// plugins are not part of what is under test.
	_ = cmd.Run() // non-zero when findings exist
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

func loadPatterns(path string) map[string]string {
	b, err := os.ReadFile(path)
	must(err)
	var rules []struct{ ID, Pattern string }
	must(json.Unmarshal(b, &rules))
	m := map[string]string{}
	for _, r := range rules {
		m[r.ID] = r.Pattern
	}
	return m
}

func summarise(res []*outcome) {
	type key struct{ format, dir, origin, reason, host string }
	count := map[key]int{}
	replayed := map[key]int{}
	for _, o := range res {
		if o.Direction == "agree" {
			continue
		}
		reason := o.Violation
		if reason == "" {
			reason = "valid:" + strings.Split(o.Variant, "/")[0]
		}
		origin := o.Origin
		if strings.HasPrefix(origin, "detector:") {
			origin = "detector"
		}
		k := key{o.Format, o.Direction, origin, reason, o.Host}
		count[k]++
		if o.Replayed != nil && *o.Replayed {
			replayed[k]++
		}
	}
	var keys []key
	for k := range count {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
	total := map[string]int{}
	for _, o := range res {
		total[o.Direction]++
	}
	fmt.Printf("candidates=%d %v\n", len(res), total)
	for _, k := range keys {
		fmt.Printf("%-22s %-9s %-9s %-28s %-24s n=%-3d replayed=%d\n", k.format, k.dir, k.origin, k.reason, k.host, count[k], replayed[k])
	}
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
