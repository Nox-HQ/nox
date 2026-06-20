package oci

import (
	"os"
	"path/filepath"
	"strings"
)

// metadataFile reports whether a file in an extracted plugin archive is
// packaging metadata (license, docs, manifests, signatures) rather than the
// executable.
func metadataFile(name string) bool {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".md"),
		strings.HasSuffix(lower, ".yaml"),
		strings.HasSuffix(lower, ".yml"),
		strings.HasSuffix(lower, ".json"),
		strings.HasSuffix(lower, ".txt"),
		strings.HasSuffix(lower, ".sig"),
		strings.HasSuffix(lower, ".pem"),
		strings.HasSuffix(lower, ".sbom"),
		lower == "license",
		strings.HasPrefix(lower, "license."),
		strings.HasPrefix(lower, "readme"),
		strings.HasPrefix(lower, "changelog"):
		return true
	}
	return false
}

// isExecutableFile reports whether path is a regular file with an executable
// permission bit set.
func isExecutableFile(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return false
	}
	return fi.Mode().Perm()&0o111 != 0
}

// findPluginBinary locates the plugin executable inside an extracted archive.
//
// goreleaser names the binary after the plugin's repository (e.g.
// "nox-plugin-taint-analysis"), not its short registry name ("taint-analysis"),
// so a fixed base-name guess misses it — leaving BinaryPath pointing at a file
// that does not exist and the plugin failing to start. Resolution order:
//
//  1. a file matching the plugin's short name (the simple case),
//  2. an executable whose name contains the short name,
//  3. the sole executable in the directory.
//
// Falls back to the short-name path (which then fails loudly at registration)
// when the directory is unreadable or the binary is genuinely ambiguous.
func findPluginBinary(extractDir, name string) string {
	short := filepath.Base(name)

	exact := filepath.Join(extractDir, short)
	if isExecutableFile(exact) {
		return exact
	}

	entries, err := os.ReadDir(extractDir)
	if err != nil {
		return exact
	}
	var execs []string
	for _, e := range entries {
		if e.IsDir() || metadataFile(e.Name()) {
			continue
		}
		p := filepath.Join(extractDir, e.Name())
		if isExecutableFile(p) {
			execs = append(execs, p)
		}
	}
	for _, p := range execs {
		if strings.Contains(filepath.Base(p), short) {
			return p
		}
	}
	if len(execs) == 1 {
		return execs[0]
	}
	return exact
}
