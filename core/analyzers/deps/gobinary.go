package deps

import (
	"bytes"
	"debug/buildinfo"
	"fmt"
	"io"
	"os"
	"strings"
)

// Compiled Go executables are inventoried from the build information the Go
// toolchain embeds in every binary it links (`go version -m` prints the same
// record): the main module, every dependency module at the version that was
// built, and the Go release, which fixes the standard library's version
// exactly. Reading it is a parse of the executable's data, with the standard
// library's debug/buildinfo. Nothing is executed.
//
// It is what a release SBOM describes (what shipped, not what go.mod
// declares), and it is the only place the standard library's version is
// stated: no go.mod names it, so without a binary nox matches no advisory
// against `stdlib` at all.

// minGoBinarySize is the smallest file considered. The smallest Go executable
// the toolchain produces, a stripped hello world, is over a megabyte; anything
// under this is not one, and skipping it keeps the probe off the many small
// files every tree has.
const minGoBinarySize = 256 << 10

// executableMagic is the leading bytes of the object formats Go links:
// ELF, Mach-O (32/64-bit, either byte order, and universal), and PE.
var executableMagic = [][]byte{
	[]byte("\x7fELF"),
	{0xfe, 0xed, 0xfa, 0xce}, {0xce, 0xfa, 0xed, 0xfe},
	{0xfe, 0xed, 0xfa, 0xcf}, {0xcf, 0xfa, 0xed, 0xfe},
	{0xca, 0xfe, 0xba, 0xbe},
	[]byte("MZ"),
}

// goBinary is what one executable contributed.
type goBinary struct {
	packages []Package
	// localReplaces names modules replaced by a local directory. The binary
	// records no version for those, so they cannot be checked.
	localReplaces []string
}

// looksExecutable reports whether path starts with an executable header.
func looksExecutable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }() // read-only
	head := make([]byte, 4)
	if _, err := io.ReadFull(f, head); err != nil {
		return false
	}
	for _, m := range executableMagic {
		if bytes.HasPrefix(head, m) {
			return true
		}
	}
	return false
}

// readGoBinary reads the build info of the Go executable at path. A file that
// is too small, is not an executable, or is an executable not built by Go
// returns an error; callers treat every error as "not a Go binary".
func readGoBinary(path string, size int64) (goBinary, error) {
	if size < minGoBinarySize || !looksExecutable(path) {
		return goBinary{}, fmt.Errorf("not an executable")
	}
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return goBinary{}, err
	}
	var out goBinary
	add := func(name, version string) {
		out.packages = append(out.packages, Package{Name: name, Version: version, Ecosystem: "go", Origin: OriginGoBinary})
	}
	if v := goReleaseVersion(bi.GoVersion); v != "" {
		add("stdlib", v)
	}
	// A main module built from a working tree records "(devel)", which is no
	// version an advisory can match.
	if m := bi.Main; m.Path != "" && m.Version != "" && m.Version != "(devel)" {
		add(m.Path, m.Version)
	}
	for _, d := range bi.Deps {
		name, version := d.Path, d.Version
		if d.Replace != nil {
			if d.Replace.Version == "" {
				out.localReplaces = append(out.localReplaces, d.Path)
				continue
			}
			// The replacement's code is what was linked.
			name, version = d.Replace.Path, d.Replace.Version
		}
		if name != "" && version != "" {
			add(name, version)
		}
	}
	return out, nil
}

// goReleaseVersion turns a toolchain version ("go1.26.2", possibly followed by
// build settings such as " X:nocoverageredesign") into the version the Go
// vulnerability database uses for stdlib ("1.26.2"). A development toolchain
// ("devel ...") has no release version and yields "".
func goReleaseVersion(v string) string {
	fields := strings.Fields(v)
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "go1") {
		return ""
	}
	return strings.TrimPrefix(fields[0], "go")
}
