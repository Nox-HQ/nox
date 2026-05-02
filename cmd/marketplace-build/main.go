// marketplace-build renders the public marketplace static site from
// registry-scaffold/index.json. Output is a directory of static
// HTML/CSS suitable for GitHub Pages deployment. No SaaS, no JS
// runtime dependency — the same JSON the CLI consumes drives the
// human-facing site.
//
// Usage:
//
//	go run ./cmd/marketplace-build \
//	    --index registry-scaffold/index.json \
//	    --output marketplace/dist
package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nox-hq/nox/registry"
)

//go:embed templates/*.html assets/*
var templateFS embed.FS

// page is the data struct passed to every template render.
type page struct {
	Title       string
	Description string
	Generated   string
	Plugins     []registry.PluginEntry
	Plugin      *registry.PluginEntry // for detail pages
	BaseURL     string
}

func main() {
	var (
		indexPath string
		outDir    string
		baseURL   string
	)
	flag.StringVar(&indexPath, "index", "registry-scaffold/index.json", "registry index JSON")
	flag.StringVar(&outDir, "output", "marketplace/dist", "output directory for the rendered site")
	flag.StringVar(&baseURL, "base-url", "", "base URL prefix when hosted under a sub-path (e.g. /nox)")
	flag.Parse()

	raw, err := os.ReadFile(indexPath)
	if err != nil {
		fatal("reading %s: %v", indexPath, err)
	}
	var idx registry.Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		fatal("parsing %s: %v", indexPath, err)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fatal("creating output: %v", err)
	}

	plugins := append([]registry.PluginEntry(nil), idx.Plugins...)
	sort.Slice(plugins, func(i, j int) bool {
		return plugins[i].Name < plugins[j].Name
	})

	tmpl, err := template.New("base").Funcs(funcs()).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		fatal("parsing templates: %v", err)
	}

	if err := writeFile(filepath.Join(outDir, "index.html"), tmpl, "index.html", page{
		Title:       "Nox Plugin Marketplace",
		Description: "Curated registry of open-source security plugins for the nox scanner. Polyglot AI security, OWASP LLM Top 10, reachability, compliance, runtime, and more.",
		Generated:   time.Now().UTC().Format("2006-01-02"),
		Plugins:     plugins,
		BaseURL:     baseURL,
	}); err != nil {
		fatal("writing index: %v", err)
	}

	for i := range plugins {
		p := plugins[i]
		slug := pluginSlug(p.Name)
		path := filepath.Join(outDir, "plugins", slug+".html")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fatal("mkdir: %v", err)
		}
		if err := writeFile(path, tmpl, "plugin.html", page{
			Title:       p.Name + " — Nox Plugin",
			Description: p.Description,
			Plugin:      &p,
			BaseURL:     baseURL,
		}); err != nil {
			fatal("writing %s: %v", path, err)
		}
	}

	// Copy embedded assets.
	if err := copyAssets(outDir); err != nil {
		fatal("copying assets: %v", err)
	}

	// Copy the source index.json so consumers (other than nox) can
	// fetch the same data the CLI uses.
	if err := copyFile(indexPath, filepath.Join(outDir, "index.json")); err != nil {
		fatal("copying index: %v", err)
	}

	fmt.Printf("[marketplace] wrote %s (%d plugins)\n", outDir, len(plugins))
}

func writeFile(path string, tmpl *template.Template, name string, data page) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // best-effort
	return tmpl.ExecuteTemplate(f, name, data)
}

func copyAssets(outDir string) error {
	return fsWalk("assets", func(rel string, body []byte) error {
		dst := filepath.Join(outDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, body, 0o644)
	})
}

func fsWalk(root string, fn func(rel string, body []byte) error) error {
	entries, err := templateFS.ReadDir(root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		body, err := templateFS.ReadFile(root + "/" + e.Name())
		if err != nil {
			return err
		}
		if err := fn(filepath.Join(root, e.Name()), body); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close() //nolint:errcheck // best-effort
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close() //nolint:errcheck // best-effort
	_, err = io.Copy(out, in)
	return err
}

// pluginSlug converts "nox/ai-eval" → "nox--ai-eval" for use in URLs.
func pluginSlug(name string) string {
	return strings.ReplaceAll(name, "/", "--")
}

func funcs() template.FuncMap {
	return template.FuncMap{
		"slug":      pluginSlug,
		"join":      strings.Join,
		"trackName": trackDisplayName,
		"hasTag": func(tags []string, target string) bool {
			for _, t := range tags {
				if t == target {
					return true
				}
			}
			return false
		},
		"firstVersion": func(p *registry.PluginEntry) registry.VersionEntry {
			if len(p.Versions) > 0 {
				return p.Versions[0]
			}
			return registry.VersionEntry{}
		},
		"installCmd": func(name string) string {
			return "nox plugin install " + name
		},
		"riskColor": func(rc string) string {
			switch rc {
			case "active":
				return "#ffcccc"
			case "passive":
				return "#e8f4ff"
			case "runtime":
				return "#ffe0b3"
			}
			return "#eee"
		},
	}
}

func trackDisplayName(t registry.Track) string {
	switch t {
	case registry.TrackCoreAnalysis:
		return "Core Analysis"
	case registry.TrackDynamicRuntime:
		return "Dynamic / Runtime"
	case registry.TrackAISecurity:
		return "AI Security"
	case registry.TrackThreatModeling:
		return "Threat Modeling"
	case registry.TrackSupplyChain:
		return "Supply Chain"
	case registry.TrackIntelligence:
		return "Intelligence"
	case registry.TrackPolicyGovernance:
		return "Policy / Governance"
	case registry.TrackIncidentReadiness:
		return "Incident Readiness"
	case registry.TrackDeveloperExperience:
		return "Developer Experience"
	case registry.TrackAgentAssistance:
		return "Agent Assistance"
	}
	return string(t)
}

func fatal(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+msg+"\n", args...)
	os.Exit(2)
}
