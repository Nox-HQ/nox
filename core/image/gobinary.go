package image

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"runtime/debug"
	"sort"
	"strings"
)

// Go executables inside an image are read for the build info the toolchain
// embeds in every binary (what `go version -m` prints): the Go release, which
// fixes the standard library's version, and every module linked. The layer is
// a stream, so the record is found by its magic while the file goes past and
// nothing is written to disk. Go 1.18 and later store the two strings inline
// after a 32-byte header; an older binary stores pointers, which a stream
// cannot follow, and is skipped.

// minGoBinarySize is the smallest file probed: a stripped Go hello world is
// over a megabyte, and the probe stays off the many small executables (shell
// scripts, tiny C tools) every image has.
const minGoBinarySize = 256 << 10

// maxBuildInfoString bounds the version and module strings: a real module
// list is kilobytes.
const maxBuildInfoString = 1 << 20

var (
	buildInfoMagic = []byte("\xff Go buildinf:")
	// executableMagic is ELF and Mach-O: what an image's Linux binaries are,
	// and what a mistakenly copied macOS one is.
	executableMagic = [][]byte{
		[]byte("\x7fELF"),
		{0xfe, 0xed, 0xfa, 0xcf}, {0xcf, 0xfa, 0xed, 0xfe},
		{0xfe, 0xed, 0xfa, 0xce}, {0xce, 0xfa, 0xed, 0xfe},
	}
)

// goBuildInfoTag starts the value kept for a Go binary in the layer file map,
// which no package database starts with.
const goBuildInfoTag = "\x00go-buildinfo\x00"

const buildInfoHeaderSize = 32

// readGoBuildInfo scans r for a Go build-info record and returns it encoded
// for the file map. ok is false for anything that is not a Go 1.18+
// executable.
func readGoBuildInfo(r io.Reader) (encoded []byte, ok bool) {
	br := bufio.NewReaderSize(r, 64<<10)
	head, err := br.Peek(4)
	if err != nil || !isExecutable(head) {
		return nil, false
	}
	keep := len(buildInfoMagic) - 1
	window := make([]byte, 0, 128<<10)
	buf := make([]byte, 64<<10)
	for {
		n, err := br.Read(buf)
		window = append(window, buf[:n]...)
		if i := bytes.Index(window, buildInfoMagic); i >= 0 {
			return parseBuildInfo(io.MultiReader(bytes.NewReader(window[i:]), br))
		}
		if err != nil {
			return nil, false
		}
		if len(window) > keep {
			window = append(window[:0], window[len(window)-keep:]...)
		}
	}
}

func isExecutable(head []byte) bool {
	for _, m := range executableMagic {
		if bytes.HasPrefix(head, m) {
			return true
		}
	}
	return false
}

// parseBuildInfo reads the header at the magic and the inline strings after
// it, as debug/buildinfo does for the inline format.
func parseBuildInfo(r io.Reader) ([]byte, bool) {
	hdr := make([]byte, buildInfoHeaderSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, false
	}
	const flagsInline = 0x2
	if ptr := hdr[14]; (ptr != 4 && ptr != 8) || hdr[15]&flagsInline == 0 {
		return nil, false
	}
	br := bufio.NewReader(r)
	version, ok := readVarString(br)
	if !ok || !strings.HasPrefix(version, "go") {
		return nil, false
	}
	mod, ok := readVarString(br)
	if !ok {
		return nil, false
	}
	// The module string is framed by 16 sentinel bytes on each side.
	if len(mod) >= 33 && mod[len(mod)-17] == '\n' {
		mod = mod[16 : len(mod)-16]
	} else {
		mod = ""
	}
	return []byte(goBuildInfoTag + version + "\x00" + mod), true
}

func readVarString(br *bufio.Reader) (string, bool) {
	n, err := binary.ReadUvarint(br)
	if err != nil || n > maxBuildInfoString {
		return "", false
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(br, b); err != nil {
		return "", false
	}
	return string(b), true
}

// goBinaryPackages lists what the Go binaries kept in files linked.
func goBinaryPackages(files map[string][]byte) []Package {
	var paths []string
	for p, b := range files {
		if bytes.HasPrefix(b, []byte(goBuildInfoTag)) {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	var out []Package
	for _, p := range paths {
		version, mod, _ := strings.Cut(strings.TrimPrefix(string(files[p]), goBuildInfoTag), "\x00")
		add := func(name, v string) {
			out = append(out, Package{Name: name, Version: v, Ecosystem: "go", Path: p})
		}
		if f := strings.Fields(version); len(f) > 0 && strings.HasPrefix(f[0], "go1") {
			add("stdlib", strings.TrimPrefix(f[0], "go"))
		}
		bi, err := debug.ParseBuildInfo(mod)
		if err != nil {
			continue
		}
		if m := bi.Main; m.Path != "" && m.Version != "" && m.Version != "(devel)" {
			add(m.Path, m.Version)
		}
		for _, d := range bi.Deps {
			name, v := d.Path, d.Version
			if d.Replace != nil {
				if d.Replace.Version == "" {
					continue // a local directory: no version to check
				}
				name, v = d.Replace.Path, d.Replace.Version
			}
			if name != "" && v != "" {
				add(name, v)
			}
		}
	}
	return out
}
