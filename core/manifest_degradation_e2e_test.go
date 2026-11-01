package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A recognised dependency manifest that nox did not turn into dependencies must
// reach meta.degradations through the real discovery + scan pipeline. Reading
// the artifact list by hand would not prove discovery hands the file over.
func TestScan_ManifestNeverReadIsADegradation(t *testing.T) {
	manifests := map[string]string{
		"Cargo.toml":     "[dependencies]\nsmallvec = \"=1.6.0\"\n",
		"pyproject.toml": "[project]\ndependencies = [\"django==2.2.0\"]\n",
		"composer.json":  `{"require":{"monolog/monolog":"1.25.0"}}`,
		"Gemfile":        "gem 'nokogiri', '1.8.0'\n",
		"pubspec.yaml":   "dependencies:\n  http: 0.13.0\n",
		"App.csproj":     `<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1"/></ItemGroup></Project>`,
		"Package.swift":  "// swift-tools-version:5.5\n",
		"mix.exs":        "defmodule X.MixProject do\nend\n",
		"build.sbt":      "libraryDependencies += \"org.scala-lang\" % \"scala-library\" % \"2.13.0\"\n",
		"conanfile.txt":  "[requires]\nzlib/1.2.11\n",
	}
	for name, body := range manifests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			res, err := RunScanContext(context.Background(), dir, ScanOptions{Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range res.Degradations {
				if string(d.Kind) == "lockfile_parse" && strings.Contains(d.Detail, name) {
					return
				}
			}
			t.Errorf("no lockfile_parse degradation names %s; degradations: %+v", name, res.Degradations)
		})
	}
}
