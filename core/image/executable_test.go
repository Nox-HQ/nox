package image

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// elfSpec describes a generated ELF64 file shaped like the real ones that
// carry OpenSSL's version text: the library names early (.dynstr), the
// version text in the middle, the dynamic section late. node's dynstr ends at
// 10 MB and its dynamic section starts at 113 MB.
type elfSpec struct {
	needed   []string
	soname   string
	text     []string // version texts, each NUL-terminated in the file
	static   bool     // no dynamic section at all
	padStart int      // bytes between the program headers and .dynstr
	padEarly int      // bytes between .dynstr and the text
	padLate  int      // bytes between the text and .dynamic
}

const fixtureVaddr = 0x400000

// buildELF writes spec as an ELF64 little-endian file with section headers,
// so debug/elf can read back what the fixture claims.
func buildELF(t *testing.T, spec elfSpec) []byte {
	t.Helper()
	le := binary.LittleEndian
	const ehsize, phsize, shsize = 64, 56, 64
	phnum := 2
	if spec.static {
		phnum = 1
	}
	var out bytes.Buffer
	out.Write(make([]byte, ehsize+phnum*phsize))
	out.Write(bytes.Repeat([]byte{'Z'}, spec.padStart))

	dynstrOff := out.Len()
	strOff := map[string]int{}
	out.WriteByte(0)
	for _, n := range append(append([]string{}, spec.needed...), spec.soname) {
		if n == "" {
			continue
		}
		if _, ok := strOff[n]; !ok {
			strOff[n] = out.Len() - dynstrOff
			out.WriteString(n + "\x00")
		}
	}
	dynstrSize := out.Len() - dynstrOff

	out.Write(bytes.Repeat([]byte{'A'}, spec.padEarly))
	for _, tx := range spec.text {
		out.WriteString("version: " + tx + "\x00")
	}
	out.Write(bytes.Repeat([]byte{'B'}, spec.padLate))
	for out.Len()%8 != 0 {
		out.WriteByte(0)
	}

	dynOff := out.Len()
	entry := func(tag elf.DynTag, val uint64) {
		var e [16]byte
		le.PutUint64(e[0:], uint64(tag))
		le.PutUint64(e[8:], val)
		out.Write(e[:])
	}
	if !spec.static {
		for _, n := range spec.needed {
			entry(elf.DT_NEEDED, uint64(strOff[n]))
		}
		if spec.soname != "" {
			entry(elf.DT_SONAME, uint64(strOff[spec.soname]))
		}
		entry(elf.DT_STRTAB, uint64(fixtureVaddr+dynstrOff))
		entry(elf.DT_NULL, 0)
	}
	dynSize := out.Len() - dynOff

	shstrOff := out.Len()
	out.WriteString("\x00.dynstr\x00.dynamic\x00.shstrtab\x00")
	shstrSize := out.Len() - shstrOff
	for out.Len()%8 != 0 {
		out.WriteByte(0)
	}
	shoff := out.Len()
	sh := func(name uint32, typ elf.SectionType, addr, off, size uint64, link uint32, entsize uint64) {
		var s [shsize]byte
		le.PutUint32(s[0:], name)
		le.PutUint32(s[4:], uint32(typ))
		le.PutUint64(s[16:], addr)
		le.PutUint64(s[24:], off)
		le.PutUint64(s[32:], size)
		le.PutUint32(s[40:], link)
		le.PutUint64(s[56:], entsize)
		out.Write(s[:])
	}
	sh(0, elf.SHT_NULL, 0, 0, 0, 0, 0)
	sh(1, elf.SHT_STRTAB, uint64(fixtureVaddr+dynstrOff), uint64(dynstrOff), uint64(dynstrSize), 0, 0)
	if spec.static {
		sh(9, elf.SHT_PROGBITS, 0, uint64(dynOff), 0, 0, 0)
	} else {
		sh(9, elf.SHT_DYNAMIC, uint64(fixtureVaddr+dynOff), uint64(dynOff), uint64(dynSize), 1, 16)
	}
	sh(18, elf.SHT_STRTAB, 0, uint64(shstrOff), uint64(shstrSize), 0, 0)

	b := out.Bytes()
	copy(b, "\x7fELF\x02\x01\x01")
	le.PutUint16(b[16:], uint16(elf.ET_DYN))
	le.PutUint16(b[18:], uint16(elf.EM_X86_64))
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[32:], ehsize)
	le.PutUint64(b[40:], uint64(shoff))
	le.PutUint16(b[52:], ehsize)
	le.PutUint16(b[54:], phsize)
	le.PutUint16(b[56:], uint16(phnum))
	le.PutUint16(b[58:], shsize)
	le.PutUint16(b[60:], 4)
	le.PutUint16(b[62:], 3)
	ph := func(i int, typ elf.ProgType, off, vaddr, size uint64) {
		p := b[ehsize+i*phsize:]
		le.PutUint32(p[0:], uint32(typ))
		le.PutUint64(p[8:], off)
		le.PutUint64(p[16:], vaddr)
		le.PutUint64(p[24:], vaddr)
		le.PutUint64(p[32:], size)
		le.PutUint64(p[40:], size)
	}
	ph(0, elf.PT_LOAD, 0, fixtureVaddr, uint64(len(b)))
	if !spec.static {
		ph(1, elf.PT_DYNAMIC, uint64(dynOff), uint64(fixtureVaddr+dynOff), uint64(dynSize))
	}

	// The fixture is only evidence if the real ELF reader agrees with it.
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("generated ELF does not parse: %v", err)
	}
	libs, err := f.ImportedLibraries()
	if err != nil && !spec.static {
		t.Fatalf("debug/elf cannot read the fixture's libraries: %v", err)
	}
	if len(libs) != len(spec.needed) || (len(libs) > 0 && !reflect.DeepEqual(libs, spec.needed)) {
		t.Fatalf("debug/elf reads the fixture as needing %v, the test claims %v", libs, spec.needed)
	}
	return b
}

const ossl359 = "OpenSSL 3.5.9 29 Sep 2026"

func TestBundledOpenSSLDecision(t *testing.T) {
	nodeNeeds := []string{"libstdc++.so.6", "libgcc_s.so.1", "libc.musl-x86_64.so.1"}
	cases := []struct {
		name     string
		path     string
		spec     elfSpec
		want     string
		wantNote string
	}{
		{"node: static OpenSSL, dynamic libc", "usr/local/bin/node",
			elfSpec{needed: nodeNeeds, text: []string{ossl359}}, "3.5.9", ""},
		{"fully static", "app/server",
			elfSpec{static: true, text: []string{ossl359}}, "3.5.9", ""},
		{"nginx: built against the system libcrypto", "usr/sbin/nginx",
			elfSpec{needed: []string{"libssl.so.3", "libcrypto.so.3", "libc.so.6"}, text: []string{"OpenSSL 3.0.15 3 Sep 2024"}}, "", ""},
		{"libssh: needs libcrypto only", "usr/lib64/libssh.so.4.9.4",
			elfSpec{needed: []string{"libcrypto.so.3", "libc.so.6"}, soname: "libssh.so.4", text: []string{"OpenSSL 3.0.7 1 Nov 2022"}}, "", ""},
		{"the distribution's libcrypto", "usr/lib/x86_64-linux-gnu/libcrypto.so.3",
			elfSpec{needed: []string{"libc.so.6"}, soname: "libcrypto.so.3", text: []string{ossl359}}, "", ""},
		{"the distribution's libcrypto, lib64", "usr/lib64/libcrypto.so.3.5.8",
			elfSpec{needed: []string{"libc.so.6"}, soname: "libcrypto.so.3", text: []string{"OpenSSL 3.5.8 1 Jul 2026"}}, "", ""},
		{"a vendored libcrypto is bundled", "opt/app/lib/libcrypto.so.3",
			elfSpec{needed: []string{"libc.so.6"}, soname: "libcrypto.so.3", text: []string{ossl359}}, "3.5.9", ""},
		{"quictls is its OpenSSL release", "usr/local/bin/node",
			elfSpec{needed: nodeNeeds, text: []string{"OpenSSL 3.0.15+quic 3 Sep 2024"}}, "3.0.15", ""},
		{"a development build is not a release", "usr/local/bin/x",
			elfSpec{needed: nodeNeeds, text: []string{"OpenSSL 3.6.0-dev  1 Jan 2026"}}, "", "not a release"},
		{"OpenSSL 1.1.1 is not checked", "usr/local/bin/x",
			elfSpec{needed: nodeNeeds, text: []string{"OpenSSL 1.1.1w  11 Sep 2023"}}, "", "only OpenSSL 3"},
		{"two versions", "usr/local/bin/x",
			elfSpec{needed: nodeNeeds, text: []string{ossl359, "OpenSSL 3.0.15 3 Sep 2024"}}, "", "more than one"},
		{"a needed library not named *.so", "usr/local/bin/x",
			elfSpec{needed: []string{"libweird"}, text: []string{ossl359}}, "", "not established"},
		{"no version text", "usr/local/bin/x",
			elfSpec{needed: nodeNeeds}, "", ""},
		{"BoringSSL's text is not OpenSSL's", "usr/local/bin/x",
			elfSpec{needed: nodeNeeds, text: []string{"OpenSSL 1.1.1 (compatible; BoringSSL)"}}, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := probeExecutable(bytes.NewReader(buildELF(t, c.spec)), c.path)
			if got.OpenSSL != c.want {
				t.Errorf("OpenSSL %q, want %q (note %q)", got.OpenSSL, c.want, got.Note)
			}
			if (c.wantNote == "") != (got.Note == "") || !strings.Contains(got.Note, c.wantNote) {
				t.Errorf("note %q, want one containing %q", got.Note, c.wantNote)
			}
		})
	}
}

// The file streams in 64 KiB pieces with a 512-byte overlap. A library name,
// the version text or the dynamic section cut by a piece boundary must read
// the same as one that is not.
func TestBundledOpenSSLAcrossChunkBoundaries(t *testing.T) {
	for _, pad := range []int{0, 1, scanChunk - 400, scanChunk - 300, scanChunk - 200, scanChunk - 100, scanChunk - 30, scanChunk - 7, scanChunk, 2*scanChunk - 13, 3*scanChunk - 250} {
		for _, late := range []int{0, scanChunk - 600, scanChunk - 40, scanChunk + 3} {
			for _, needed := range [][]string{
				{"libc.musl-x86_64.so.1"},
				{"libssl.so.3", "libcrypto.so.3", "libc.so.6"},
			} {
				spec := elfSpec{needed: needed, text: []string{ossl359}, padEarly: pad, padLate: late}
				want := "3.5.9"
				if len(needed) > 1 {
					want = ""
				}
				got := probeExecutable(bytes.NewReader(buildELF(t, spec)), "usr/local/bin/x")
				if got.OpenSSL != want || got.Note != "" {
					t.Errorf("pad %d/%d needs %v: OpenSSL %q note %q, want %q", pad, late, needed, got.OpenSSL, got.Note, want)
				}
			}
		}
	}
	// Library names straddling a boundary: .dynstr shifted so that
	// "libcrypto.so.3" starts at every offset from 20 bytes before the first
	// boundary to past it.
	needed := []string{"libssl.so.3", "libcrypto.so.3", "libc.so.6"}
	firstName := 64 + 2*56 + 1 // header, two program headers, dynstr's NUL
	for shift := scanChunk - firstName - len("libssl.so.3\x00") - 20; shift < scanChunk-firstName+4; shift++ {
		got := probeExecutable(bytes.NewReader(buildELF(t, elfSpec{needed: needed, text: []string{ossl359}, padStart: shift})), "usr/local/bin/x")
		if got.OpenSSL != "" || got.Note != "" {
			t.Errorf("dynstr shifted %d: OpenSSL %q note %q; it needs libcrypto", shift, got.OpenSSL, got.Note)
		}
	}
}

// A statically linked OpenSSL inside an image is a package at the binary's
// path; a vendored libcrypto is probed even when it is not executable.
func TestBundledOpenSSLInALayer(t *testing.T) {
	node := buildELF(t, elfSpec{needed: []string{"libstdc++.so.6", "libc.musl-x86_64.so.1"}, text: []string{ossl359}, padEarly: minExecutableSize})
	vendored := buildELF(t, elfSpec{needed: []string{"libc.so.6"}, soname: "libcrypto.so.3", text: []string{"OpenSSL 3.0.15 3 Sep 2024"}, padEarly: minExecutableSize})
	system := buildELF(t, elfSpec{needed: []string{"libc.so.6"}, soname: "libcrypto.so.3", text: []string{ossl359}, padEarly: minExecutableSize})
	reg := newRegistry(t)
	digest := reg.image(t, layer(t,
		file{name: "etc/os-release", body: alpineRelease},
		file{name: "usr/local/bin/node", body: string(node), exec: true},
		file{name: "opt/vendor/lib/libcrypto.so.3", body: string(vendored)},
		file{name: "usr/lib/libcrypto.so.3", body: string(system), exec: true},
	))
	got, err := reg.client(t).Contents(context.Background(), "golang", digest) // the test registry serves library/golang
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, p := range got.Packages {
		if p.Ecosystem == "openssl" {
			found = append(found, p.Path+"="+p.Version)
		}
	}
	want := []string{"opt/vendor/lib/libcrypto.so.3=3.0.15", "usr/local/bin/node=3.5.9"}
	if !reflect.DeepEqual(found, want) {
		t.Errorf("bundled OpenSSL %v, want %v (notes %v)", found, want, got.Notes)
	}
}

// NOX_ELF_ORACLE_DIR names a directory of real ELF files (copied out of
// images with docker cp). The streamed reading of their linked libraries
// must equal debug/elf's, which reads the file with random access.
func TestExecutableScanAgreesWithDebugELF(t *testing.T) {
	dir := os.Getenv("NOX_ELF_ORACLE_DIR")
	if dir == "" {
		t.Skip("set NOX_ELF_ORACLE_DIR to a directory of real ELF files")
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*"))
	checked := 0
	for _, p := range paths {
		f, err := elf.Open(p)
		if err != nil {
			continue
		}
		want, _ := f.ImportedLibraries()
		_ = f.Close()
		fh, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		s, ok := scanExecutable(fh)
		_ = fh.Close()
		if !ok || s.layout == nil {
			t.Errorf("%s: not read as ELF", p)
			continue
		}
		got, _, why := s.layout.dynamicNames(s)
		if why != "" || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: streamed %v (%s), debug/elf %v", filepath.Base(p), got, why, want)
		}
		ver, note := s.bundledOpenSSL("usr/local/bin/" + filepath.Base(p))
		t.Logf("%s: needs %v; bundled OpenSSL %q %s", filepath.Base(p), got, ver, note)
		checked++
	}
	if checked == 0 {
		t.Fatal("no ELF files checked")
	}
}

// A file cut short before its dynamic section ends has unknown libraries: it
// must not read as linking nothing, which would make any libcrypto user look
// like it bundles OpenSSL.
func TestTruncatedExecutableIsNotStatic(t *testing.T) {
	b := buildELF(t, elfSpec{needed: []string{"libssl.so.3", "libcrypto.so.3", "libc.so.6"}, text: []string{ossl359}})
	l, _ := parseELFLayout(b)
	cut := b[:l.dynOff+8]
	got := probeExecutable(bytes.NewReader(cut), "usr/local/bin/x")
	if got.OpenSSL != "" || !strings.Contains(got.Note, "ends before") {
		t.Errorf("cut file: OpenSSL %q note %q", got.OpenSSL, got.Note)
	}
}
