package image

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
)

// An executable in a layer is read once, as it streams past, for what it
// carries that no package database lists: a Go binary's build info, and an
// OpenSSL linked statically into it (Node.js bundles its own).
//
// OpenSSL's version text ("OpenSSL 3.5.9 29 Sep 2026") is not enough on its
// own. Programs built against a system libcrypto print the version they were
// compiled with and carry the same text: in sixteen popular images it was in
// nginx, mod_ssl, libssh and the openssl tool, every one of which loads the
// distribution's libcrypto at runtime (nginx said 3.0.15 while running
// against Debian's 3.0.16). So a file counts as bundling OpenSSL only when it
// carries the text, is not libcrypto or libssl itself, and its dynamic
// section names neither library. That section usually comes after the text
// in the file, so every NUL-terminated "*.so" string is recorded with its
// offset as it passes, and DT_NEEDED is resolved against them at the end:
// exact, and still one pass. Whatever cannot be resolved is a note, never a
// silent pass.

// executableTag starts the value kept for a probed executable in the layer
// file map, which no package database starts with.
const executableTag = "\x00executable\x00"

// minExecutableSize is the smallest file probed: a stripped Go hello world is
// over a megabyte, a statically linked OpenSSL several, and the probe stays
// off the many small executables (shell scripts, tiny C tools) every image
// has.
const minExecutableSize = 256 << 10

const (
	scanChunk   = 64 << 10
	scanOverlap = 512 // longer than any match below, so none is cut in two
	maxSOName   = 255
	maxSONames  = 1 << 16
	maxDynamic  = 1 << 20
	// goCapture bounds what is kept after the build-info magic: the header
	// and two strings of at most maxBuildInfoString, with their varints.
	goCapture = buildInfoHeaderSize + 2*maxBuildInfoString + 20
)

// opensslText is OPENSSL_VERSION_TEXT. quictls ("3.0.15+quic") is OpenSSL
// with QUIC patches on the same release; any other suffix is not a release
// OpenSSL publishes advisories by.
var opensslText = regexp.MustCompile(`^OpenSSL (\d+\.\d+\.\d+[a-z]*)([-+][\w.~+-]*)? +\d{1,2} [A-Z][a-z]{2} \d{4}`)

// sharedObject names a shared library, probed whatever its mode: a vendored
// one is often not marked executable.
var sharedObject = regexp.MustCompile(`\.so(\.\d+)*$`)

// systemLibDir is where a distribution installs its own libraries. A
// libcrypto there is the distribution's package, already read from its
// database with the distribution's backported fixes, which its upstream
// version text does not show.
var systemLibDir = regexp.MustCompile(`^(usr/)?lib(64|32)?(/[\w-]+-linux-gnu\w*)?/[^/]+$`)

// executableInfo is what one probed file carries.
type executableInfo struct {
	Go      string `json:"go,omitempty"`      // build info: version + "\x00" + module text
	OpenSSL string `json:"openssl,omitempty"` // statically linked OpenSSL release
	Note    string `json:"note,omitempty"`    // carried, but could not be established
}

func (e executableInfo) empty() bool { return e == executableInfo{} }

func encodeExecutable(e executableInfo) []byte {
	b, _ := json.Marshal(e) // strings only: cannot fail
	return append([]byte(executableTag), b...)
}

func decodeExecutable(b []byte) (executableInfo, bool) {
	var e executableInfo
	rest, ok := bytes.CutPrefix(b, []byte(executableTag))
	if !ok || json.Unmarshal(rest, &e) != nil {
		return executableInfo{}, false
	}
	return e, true
}

// probeExecutable reads one executable or shared object at name.
func probeExecutable(r io.Reader, name string) executableInfo {
	s, ok := scanExecutable(r)
	if !ok {
		return executableInfo{}
	}
	info := executableInfo{}
	if s.goBuild != nil {
		if enc, ok := parseBuildInfo(bytes.NewReader(s.goBuild)); ok {
			info.Go = strings.TrimPrefix(string(enc), goBuildInfoTag)
		}
	}
	info.OpenSSL, info.Note = s.bundledOpenSSL(name)
	return info
}

// execScan is what one pass over a file collected.
type execScan struct {
	layout   *elfLayout
	goBuild  []byte
	versions map[string]bool
	soNames  map[int64]string
	tooMany  bool
	dynamic  []byte
	dynSeen  int
}

// scanExecutable reads r once. ok is false for anything that is not an ELF
// or Mach-O file.
func scanExecutable(r io.Reader) (*execScan, bool) {
	br := bufio.NewReaderSize(r, scanChunk)
	head, _ := br.Peek(scanChunk)
	if len(head) < 4 || !isExecutable(head) {
		return nil, false
	}
	s := &execScan{versions: map[string]bool{}, soNames: map[int64]string{}}
	if l, ok := parseELFLayout(head); ok {
		s.layout = l
		if l.dynSize > 0 && l.dynSize <= maxDynamic {
			s.dynamic = make([]byte, l.dynSize)
		}
	}
	buf := make([]byte, 0, scanChunk+scanOverlap)
	fresh := make([]byte, scanChunk)
	var base int64 // file offset of buf[0]
	for {
		n, err := io.ReadFull(br, fresh)
		final := err != nil
		start := base + int64(len(buf))
		buf = append(buf, fresh[:n]...)
		s.capture(fresh[:n], start)
		s.find(buf, base, final)
		if final {
			break
		}
		if drop := len(buf) - scanOverlap; drop > 0 {
			base += int64(drop)
			buf = append(buf[:0], buf[drop:]...)
		}
	}
	return s, true
}

// capture copies the bytes at [start, start+len(b)) into the Go build-info
// and dynamic-section captures they belong to.
func (s *execScan) capture(b []byte, start int64) {
	if s.goBuild != nil && len(s.goBuild) < goCapture {
		s.goBuild = append(s.goBuild, b[:min(len(b), goCapture-len(s.goBuild))]...)
	}
	if s.dynamic != nil {
		lo, hi := int64(s.layout.dynOff), int64(s.layout.dynOff+s.layout.dynSize)
		from, to := max(lo, start), min(hi, start+int64(len(b)))
		if from < to {
			s.dynSeen += copy(s.dynamic[from-lo:], b[from-start:to-start])
		}
	}
}

// find looks for the build-info magic, OpenSSL's version text, and shared
// library names in buf, whose first byte is at file offset base. A match
// running past the end of buf is left for the next call, which sees it whole
// in the overlap.
func (s *execScan) find(buf []byte, base int64, final bool) {
	if s.goBuild == nil {
		if i := bytes.Index(buf, buildInfoMagic); i >= 0 {
			s.goBuild = append([]byte(nil), buf[i:min(len(buf), i+goCapture)]...)
		}
	}
	for off := 0; ; {
		i := bytes.Index(buf[off:], []byte("OpenSSL "))
		if i < 0 {
			break
		}
		i += off
		off = i + 1
		end := min(len(buf), i+96)
		if end == len(buf) && !final {
			continue
		}
		if m := opensslText.FindSubmatch(buf[i:end]); m != nil {
			s.versions[string(m[1])+string(m[2])] = true
		}
	}
	for off := 0; ; {
		j := bytes.Index(buf[off:], []byte(".so"))
		if j < 0 {
			break
		}
		j += off
		off = j + 3
		k := j + 3
		for k < len(buf) && (buf[k] == '.' || buf[k] >= '0' && buf[k] <= '9') {
			k++
		}
		if k >= len(buf) || buf[k] != 0 {
			continue
		}
		st := j
		for st > 0 && buf[st-1] != 0 && j-st < maxSOName {
			st--
		}
		if st == 0 || buf[st-1] != 0 || st == j {
			continue
		}
		if len(s.soNames) >= maxSONames {
			s.tooMany = true
			return
		}
		s.soNames[base+int64(st)] = string(buf[st:k])
	}
}

// bundledOpenSSL decides whether the file at name links OpenSSL statically.
func (s *execScan) bundledOpenSSL(name string) (version, note string) {
	if len(s.versions) == 0 {
		return "", ""
	}
	vs := make([]string, 0, len(s.versions))
	for v := range s.versions {
		vs = append(vs, v)
	}
	sort.Strings(vs)
	if len(vs) > 1 {
		return "", fmt.Sprintf("%s carries version text for more than one OpenSSL (%s), so which it runs is not established", name, strings.Join(vs, ", "))
	}
	v := vs[0]
	if s.layout == nil {
		return "", fmt.Sprintf("%s carries OpenSSL %s's version text but is not an ELF file nox reads, so whether it links it is not established", name, v)
	}
	needed, soname, err := s.layout.dynamicNames(s)
	if err != "" {
		return "", fmt.Sprintf("%s carries OpenSSL %s's version text; whether it links OpenSSL statically is not established: %s", name, v, err)
	}
	if isOpenSSLLib(soname) || (soname == "" && isOpenSSLLib(path.Base(name))) {
		if systemLibDir.MatchString(name) {
			return "", "" // the distribution's own, read from its package database
		}
		return releaseOrNote(name, v)
	}
	for _, n := range needed {
		if isOpenSSLLib(n) {
			return "", "" // built against the image's libcrypto, which is what runs
		}
	}
	return releaseOrNote(name, v)
}

func isOpenSSLLib(name string) bool {
	return strings.HasPrefix(name, "libcrypto.so") || strings.HasPrefix(name, "libssl.so")
}

func releaseOrNote(name, v string) (version, note string) {
	if base, ok := strings.CutSuffix(v, "+quic"); ok {
		return base, ""
	}
	if strings.ContainsAny(v, "-+") {
		return "", fmt.Sprintf("%s links OpenSSL %s, which is not a release OpenSSL publishes advisories by", name, v)
	}
	if !strings.HasPrefix(v, "3.") {
		return "", fmt.Sprintf("%s links OpenSSL %s; only OpenSSL 3 releases are checked", name, v)
	}
	return v, ""
}

// elfLayout is what an ELF file's header and program headers say about where
// its dynamic section is and how addresses map to file offsets.
type elfLayout struct {
	order   binary.ByteOrder
	class64 bool
	dynOff  uint64
	dynSize uint64
	loads   []elfLoad
}

type elfLoad struct{ vaddr, off, size uint64 }

const (
	ptLoad    = 1
	ptDynamic = 2
	dtNull    = 0
	dtNeeded  = 1
	dtStrtab  = 5
	dtSoname  = 14
)

// parseELFLayout reads the ELF header and program headers from the start of
// the file. ok is false when they are not all in head.
func parseELFLayout(head []byte) (*elfLayout, bool) {
	if len(head) < 52 || !bytes.HasPrefix(head, []byte("\x7fELF")) {
		return nil, false
	}
	l := &elfLayout{}
	switch head[4] {
	case 1:
	case 2:
		l.class64 = true
	default:
		return nil, false
	}
	switch head[5] {
	case 1:
		l.order = binary.LittleEndian
	case 2:
		l.order = binary.BigEndian
	default:
		return nil, false
	}
	var phoff uint64
	var phentsize, phnum, minEntry int
	if l.class64 {
		if len(head) < 64 {
			return nil, false
		}
		phoff = l.order.Uint64(head[32:40])
		phentsize, phnum, minEntry = int(l.order.Uint16(head[54:56])), int(l.order.Uint16(head[56:58])), 56
	} else {
		phoff = uint64(l.order.Uint32(head[28:32]))
		phentsize, phnum, minEntry = int(l.order.Uint16(head[42:44])), int(l.order.Uint16(head[44:46])), 32
	}
	if phentsize < minEntry || phnum == 0xffff || phoff+uint64(phentsize*phnum) > uint64(len(head)) {
		return nil, false
	}
	for i := 0; i < phnum; i++ {
		ph := head[phoff+uint64(i*phentsize):]
		var typ uint32
		var off, vaddr, size uint64
		if l.class64 {
			typ, off, vaddr, size = l.order.Uint32(ph[0:4]), l.order.Uint64(ph[8:16]), l.order.Uint64(ph[16:24]), l.order.Uint64(ph[32:40])
		} else {
			typ, off, vaddr, size = l.order.Uint32(ph[0:4]), uint64(l.order.Uint32(ph[4:8])), uint64(l.order.Uint32(ph[8:12])), uint64(l.order.Uint32(ph[16:20]))
		}
		switch typ {
		case ptLoad:
			l.loads = append(l.loads, elfLoad{vaddr: vaddr, off: off, size: size})
		case ptDynamic:
			l.dynOff, l.dynSize = off, size
		}
	}
	return l, true
}

// dynamicNames resolves DT_NEEDED and DT_SONAME against the names recorded
// while the file streamed. A file with no dynamic section links nothing at
// runtime. err says why the names could not be established.
func (l *elfLayout) dynamicNames(s *execScan) (needed []string, soname, err string) {
	if l.dynSize == 0 {
		return nil, "", ""
	}
	switch {
	case s.dynamic == nil:
		return nil, "", fmt.Sprintf("its dynamic section is %d bytes, over the %d-byte limit", l.dynSize, maxDynamic)
	case s.dynSeen != len(s.dynamic):
		return nil, "", "the file ends before its dynamic section does"
	case s.tooMany:
		return nil, "", fmt.Sprintf("it holds over %d library names", maxSONames)
	}
	entry := 8
	if l.class64 {
		entry = 16
	}
	var neededOff []uint64
	var sonameOff, strtab uint64
	hasSoname, hasStrtab := false, false
	for p := 0; p+entry <= len(s.dynamic); p += entry {
		var tag, val uint64
		if l.class64 {
			tag, val = l.order.Uint64(s.dynamic[p:]), l.order.Uint64(s.dynamic[p+8:])
		} else {
			tag, val = uint64(l.order.Uint32(s.dynamic[p:])), uint64(l.order.Uint32(s.dynamic[p+4:]))
		}
		if tag == dtNull {
			break
		}
		switch tag {
		case dtNeeded:
			neededOff = append(neededOff, val)
		case dtSoname:
			sonameOff, hasSoname = val, true
		case dtStrtab:
			strtab, hasStrtab = val, true
		}
	}
	if len(neededOff) == 0 && !hasSoname {
		return nil, "", ""
	}
	if !hasStrtab {
		return nil, "", "its dynamic section has no string table"
	}
	base, ok := l.fileOffset(strtab)
	if !ok {
		return nil, "", "its string table is outside every loaded segment"
	}
	name := func(off uint64) (string, bool) {
		n, ok := s.soNames[int64(base+off)]
		return n, ok
	}
	for _, off := range neededOff {
		n, ok := name(off)
		if !ok {
			return nil, "", "a library it needs is not named like a shared object"
		}
		needed = append(needed, n)
	}
	if hasSoname {
		soname, _ = name(sonameOff) // a SONAME not shaped like *.so is no OpenSSL
	}
	return needed, soname, ""
}

func (l *elfLayout) fileOffset(vaddr uint64) (uint64, bool) {
	for _, ld := range l.loads {
		if vaddr >= ld.vaddr && vaddr < ld.vaddr+ld.size {
			return ld.off + (vaddr - ld.vaddr), true
		}
	}
	return 0, false
}

// executablePackages lists what the probed executables in files carry, and
// the notes for what they carry but could not be established.
func executablePackages(files map[string][]byte) (pkgs []Package, notes []string) {
	var paths []string
	for p, b := range files {
		if bytes.HasPrefix(b, []byte(executableTag)) {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		e, ok := decodeExecutable(files[p])
		if !ok {
			continue
		}
		if e.Go != "" {
			pkgs = append(pkgs, goBuildPackages(p, e.Go)...)
		}
		if e.OpenSSL != "" {
			pkgs = append(pkgs, Package{Name: "openssl", Version: e.OpenSSL, Ecosystem: "openssl", Path: p})
		}
		if e.Note != "" {
			notes = append(notes, e.Note)
		}
	}
	return pkgs, notes
}
