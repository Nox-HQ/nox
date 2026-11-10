package image

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"runtime/debug"
	"strings"
)

// Go executables inside an image are read for the build info the toolchain
// embeds in every binary (what `go version -m` prints): the Go release, which
// fixes the standard library's version, and every module linked. The layer is
// a stream, so the record is found by its magic while the file goes past and
// nothing is written to disk. Go 1.18 and later store the two strings inline
// after a 32-byte header; an older binary stores pointers, which a stream
// cannot follow, and is skipped.

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

// goBuildPackages lists what one Go binary at p linked, from its build info
// (version + "\x00" + module text).
func goBuildPackages(p, info string) []Package {
	var out []Package
	{
		version, mod, _ := strings.Cut(info, "\x00")
		add := func(name, v string) {
			out = append(out, Package{Name: name, Version: v, Ecosystem: "go", Path: p})
		}
		if f := strings.Fields(version); len(f) > 0 && strings.HasPrefix(f[0], "go1") {
			add("stdlib", strings.TrimPrefix(f[0], "go"))
		}
		bi, err := debug.ParseBuildInfo(mod)
		if err != nil {
			return out
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
