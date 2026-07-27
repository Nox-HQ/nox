package memsafe

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// scanSource writes src to a temp file and returns the findings for it.
func scanSource(t *testing.T, name, src string) []findings.Finding {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	fs, err := (&Analyzer{}).ScanArtifacts(context.Background(),
		[]discovery.Artifact{{Path: name, AbsPath: p}})
	if err != nil {
		t.Fatal(err)
	}
	return fs.Findings()
}

func count(t *testing.T, src string) int {
	t.Helper()
	return len(scanSource(t, "a.go", src))
}

// ---------------------------------------------------------------------------
// Positives: truncation that reaches a size sink
// ---------------------------------------------------------------------------

func TestFiresOnTruncationReachingASizeSink(t *testing.T) {
	cases := []struct{ name, src string }{
		{
			// The canonical CWE-190: a wire-decoded 64-bit length narrowed to
			// int32 and handed straight to make. A length above 2^31 wraps
			// negative and panics; one crafted to wrap positive allocates a
			// buffer smaller than the caller believes.
			name: "wire length into make, inline",
			src: `package m
func f(buf []byte) []byte {
	return make([]byte, int32(binary.BigEndian.Uint64(buf)))
}`,
		},
		{
			name: "parsed length into make, through a local",
			src: `package m
func f(s string) []byte {
	n, _ := strconv.ParseInt(s, 10, 64)
	sz := int32(n)
	return make([]byte, sz)
}`,
		},
		{
			// Signed to unsigned: a negative length becomes enormous.
			name: "signed to unsigned length",
			src: `package m
func f(n int64) []byte {
	sz := uint32(n)
	return make([]byte, sz)
}`,
		},
		{
			name: "declared int64 narrowed into a slice bound",
			src: `package m
func f(buf []byte) []byte {
	var off int64 = readOffset()
	return buf[:int32(off)]
}`,
		},
		{
			name: "uint64 parameter truncated to a slice bound",
			src: `package m
func f(buf []byte, pos uint64) []byte {
	i := uint8(pos)
	return buf[i:]
}`,
		},
		{
			name: "make capacity argument counts as a size",
			src: `package m
func f(n int64) []byte {
	return make([]byte, 0, int32(n))
}`,
		},
		{
			name: "three-index slice max bound counts as a size",
			src: `package m
func f(buf []byte, n int64) []byte {
	return buf[0:1:int32(n)]
}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if n := count(t, c.src); n != 1 {
				t.Errorf("got %d findings, want 1", n)
			}
		})
	}
}

// The message and metadata must name the actual types, because that is what
// makes the finding actionable without opening the file.
func TestFindingNamesTheConversion(t *testing.T) {
	f := scanSource(t, "a.go", `package m
func f(n int64) []byte { return make([]byte, int32(n)) }`)
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
	if f[0].RuleID != ruleID {
		t.Errorf("rule ID = %q, want %q", f[0].RuleID, ruleID)
	}
	if got := f[0].Metadata["from"]; got != "int64" {
		t.Errorf("from = %q, want int64", got)
	}
	if got := f[0].Metadata["to"]; got != "int32" {
		t.Errorf("to = %q, want int32", got)
	}
	if !strings.Contains(f[0].Message, "int64 to int32") {
		t.Errorf("message %q does not name the conversion", f[0].Message)
	}
	if f[0].Location.StartLine != 2 {
		t.Errorf("line = %d, want 2", f[0].Location.StartLine)
	}
}

// ---------------------------------------------------------------------------
// Negatives: conversions that cannot lose information
// ---------------------------------------------------------------------------

func TestSilentOnConversionsThatCannotOverflow(t *testing.T) {
	cases := []struct{ name, src string }{
		{
			name: "widening keeps the value",
			src: `package m
func f(n int32) []byte { return make([]byte, int64(n)) }`,
		},
		{
			name: "byte to int is exact",
			src: `package m
func f(b byte) []byte { return make([]byte, int(b)) }`,
		},
		{
			name: "uint8 to int16 is exact",
			src: `package m
func f(b uint8) []byte { return make([]byte, int16(b)) }`,
		},
		{
			name: "uint32 to int64 is exact",
			src: `package m
func f(u uint32) []byte { return make([]byte, int64(u)) }`,
		},
		{
			name: "identity conversion",
			src: `package m
func f(n int32) []byte { return make([]byte, int32(n)) }`,
		},
		{
			name: "constant that fits",
			src: `package m
func f() []byte { return make([]byte, int32(1024)) }`,
		},
		{
			name: "constant arithmetic that fits",
			src: `package m
func f() []byte { return make([]byte, int32(4*1024+7)) }`,
		},
		{
			name: "masked to the destination width",
			src: `package m
func f(n int64, buf []byte) []byte { return buf[:uint8(n&0xFF)] }`,
		},
		{
			name: "reduced modulo a fitting constant",
			src: `package m
func f(n int64, buf []byte) []byte { return buf[:uint8(n%16)] }`,
		},
		{
			name: "reduced modulo a named constant",
			src: `package m
func f(h uint64, tab []entry) []entry { return tab[:int32(h%tableSize)] }`,
		},
		{
			name: "logical shift leaves a fitting number of bits",
			src: `package m
func f(s0 uint32, tab []byte) []byte { return tab[:uint8(s0>>24)] }`,
		},
		{
			name: "length narrowed to 32 bits is bounded by memory",
			src: `package m
func f(buf []byte) []uint16 { return make([]uint16, uint32(2*len(buf))) }`,
		},
		{
			name: "guard written through a conversion",
			src: `package m
func f(r rune, props []byte) []byte {
	if uint32(r) <= MaxLatin1 {
		return props[:uint8(r)]
	}
	return nil
}`,
		},
		{
			name: "range checked before the conversion",
			src: `package m
func f(n int64) ([]byte, error) {
	if n < 0 || n > 4096 {
		return nil, errTooBig
	}
	return make([]byte, int32(n)), nil
}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if n := count(t, c.src); n != 0 {
				t.Errorf("got %d findings, want 0", n)
			}
		})
	}
}

// A mask that is WIDER than the destination does not bound the conversion, so
// the suppression must not be a blanket "any mask is fine".
func TestMaskWiderThanDestinationStillFires(t *testing.T) {
	src := `package m
func f(n int64, buf []byte) []byte { return buf[:uint8(n&0xFFFF)] }`
	if got := count(t, src); got != 1 {
		t.Errorf("got %d findings, want 1: a 16-bit mask does not fit uint8", got)
	}
}

// A mask applied to something that is not a bare name — a call result, a field
// — is bounded by the expression itself rather than by any tracked variable.
// This is the case only the inline check covers, so assert it separately from
// the `x & 0xFF` form above, which the whole-function bound map also catches.
func TestInlineMaskOnANonIdentifierOperandSuppresses(t *testing.T) {
	src := `package m
func f(s string) []byte { return make([]byte, uint8(len(s)&0xFF)) }`
	if got := count(t, src); got != 0 {
		t.Errorf("got %d findings, want 0: len(s)&0xFF fits uint8 exactly", got)
	}
	// Control: the same shape with a mask too wide for the destination must
	// still fire, so this is not passing because the operand is unresolvable.
	wide := `package m
func f(s string) []byte { return make([]byte, uint8(len(s)&0xFFFF)) }`
	if got := count(t, wide); got != 1 {
		t.Fatalf("control: got %d findings, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// Negatives: truncation that does NOT reach a size sink
// ---------------------------------------------------------------------------

// This is the class that made gosec's G115 unusable on this fleet. Every case
// below is a verbatim shape taken from a real gosec G115 finding measured
// across sixteen fleet repositories, and every one of them is correct code.
func TestSilentOnRealWorldGosecG115FalsePositives(t *testing.T) {
	cases := []struct{ name, src string }{
		{
			// mnemos/internal/server/grpc/server.go and 40 siblings.
			name: "protobuf count field",
			src: `package m
func f(out []Row, total, limit, offset int) *pb.ListResponse {
	return &pb.ListResponse{Rows: out, Count: int32(len(out)), Total: int32(total), Limit: int32(limit), Offset: int32(offset)}
}`,
		},
		{
			// auth-go/domain/totp.go — HOTP counter, positive until year 292e9.
			name: "unix time into an HOTP counter",
			src: `package m
func f(t time.Time, period uint64) uint64 { return uint64(t.Unix()) / period }`,
		},
		{
			// scout/urlvalidator.go — IPv4 octet extraction; truncation is the point.
			name: "ipv4 octet extraction",
			src: `package m
func f(addr uint64) net.IP {
	return net.IPv4(byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr))
}`,
		},
		{
			// bolt/encode.go — digit formatting behind a modulo.
			name: "digit formatting",
			src: `package m
func f(nano int, digitBuf []byte) {
	for i := 8; i >= 0; i-- {
		digitBuf[i] = byte(nano%10) + '0'
		nano /= 10
	}
}`,
		},
		{
			// nox sdk/response.go — line/column numbers into a protobuf Location.
			name: "line numbers into a protobuf location",
			src: `package m
func f(filePath string, startLine, endLine int) *pb.Location {
	return &pb.Location{FilePath: filePath, StartLine: int32(startLine), EndLine: int32(endLine)}
}`,
		},
		{
			// nox registry/oci/extract.go — masked to 0o777 after the conversion.
			name: "file mode masked to nine bits",
			src: `package m
func f(mode int64, target string) error {
	return os.MkdirAll(target, os.FileMode(mode)&0o777|0o755)
}`,
		},
		{
			// warden internal/infrastructure/watch/watch.go — hashing a size.
			name: "size folded into a hash",
			src: `package m
func f(size int64, buf []byte) {
	binary.LittleEndian.PutUint64(buf, uint64(size))
}`,
		},
		{
			// statekit/eventstore.go — digit rendering.
			name: "int to rune for a digit",
			src: `package m
func f(v int) string { return string(rune(v + '0')) }`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if n := count(t, c.src); n != 0 {
				t.Errorf("got %d findings, want 0 — this shape is correct code", n)
			}
		})
	}
}

// A bare index expression is not a sink: it may be a map lookup, which needs
// go/types to rule out, and Go bounds-checks slice indexes anyway. Measured on
// the Go standard library this single decision removed 46 findings, all of
// them correct code. The matching slice-bound form must still fire, so the
// pair is asserted together.
func TestIndexExpressionsAreNotSizeSinksButSliceBoundsAre(t *testing.T) {
	index := `package m
func f(buf []byte, pos int64) byte { return buf[int16(pos)] }`
	if got := count(t, index); got != 0 {
		t.Errorf("index: got %d findings, want 0", got)
	}
	// The AES S-box shape, which is what made this decision necessary.
	sbox := `package m
func f(s0 uint32, te0 []uint32) uint32 { return te0[uint8(s0)] }`
	if got := count(t, sbox); got != 0 {
		t.Errorf("table index: got %d findings, want 0", got)
	}
	bound := `package m
func f(buf []byte, pos int64) []byte { return buf[:int16(pos)] }`
	if got := count(t, bound); got != 1 {
		t.Fatalf("slice bound: got %d findings, want 1", got)
	}
}

// copy and append are bounded by the slices they operate on, so a wrapped
// length there cannot index out of range. They are not sinks.
func TestCopyAndAppendAreNotSizeSinks(t *testing.T) {
	for _, src := range []string{
		`package m
func f(dst, src []byte, n int64) int { return copy(dst[:], src[:]) + int(int32(n)) }`,
		`package m
func f(xs []int32, n int64) []int32 { return append(xs, int32(n)) }`,
	} {
		if got := count(t, src); got != 0 {
			t.Errorf("got %d findings, want 0 for %q", got, src)
		}
	}
}

// ---------------------------------------------------------------------------
// Negatives: the operand's type is not locally provable
// ---------------------------------------------------------------------------

// Without go/types the type of a struct field, a named type, or a multi-value
// call result cannot be established. The rule stays silent rather than
// guessing — a deliberate false negative documented in the package comment.
func TestSilentWhenTheOperandTypeIsNotLocallyProvable(t *testing.T) {
	cases := []struct{ name, src string }{
		{
			name: "struct field from another package",
			src: `package m
func f(h *tar.Header) []byte { return make([]byte, int32(h.Size)) }`,
		},
		{
			name: "named type with an integer underlying type",
			src: `package m
func f(d time.Duration) []byte { return make([]byte, int32(d)) }`,
		},
		{
			name: "multi-value call result",
			src: `package m
func f(r io.Reader, p []byte) []byte {
	n, _ := r.Read(p)
	return make([]byte, int32(n))
}`,
		},
		{
			name: "package-level variable",
			src: `package m
var limit int64
func f() []byte { return make([]byte, int32(limit)) }`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if n := count(t, c.src); n != 0 {
				t.Errorf("got %d findings, want 0 (documented false negative)", n)
			}
		})
	}
}

// len() returns int, so int32(len(x)) IS a narrowing the analyzer can prove —
// but only reports it where it sizes memory, never where it fills a count
// field. Both halves are asserted together so a change to either is caught.
func TestLenIsProvableButOnlyReportedAtASizeSink(t *testing.T) {
	sink := `package m
func f(s string) []byte { return make([]byte, int16(len(s))) }`
	if got := count(t, sink); got != 1 {
		t.Errorf("size sink: got %d findings, want 1", got)
	}
	notSink := `package m
func f(s string) *pb.R { return &pb.R{Count: int32(len(s))} }`
	if got := count(t, notSink); got != 0 {
		t.Errorf("count field: got %d findings, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// File-level filters
// ---------------------------------------------------------------------------

func TestSkipsTestAndGeneratedAndNonGoFiles(t *testing.T) {
	body := `package m
func f(n int64) []byte { return make([]byte, int32(n)) }`

	if got := len(scanSource(t, "a_test.go", body)); got != 0 {
		t.Errorf("test file: got %d findings, want 0", got)
	}
	if got := len(scanSource(t, "a.py", body)); got != 0 {
		t.Errorf("non-Go file: got %d findings, want 0", got)
	}
	gen := "// Code generated by protoc-gen-go. DO NOT EDIT.\n" + body
	if got := len(scanSource(t, "a.pb.go", gen)); got != 0 {
		t.Errorf("generated file: got %d findings, want 0", got)
	}
	// Control: the same body in an ordinary file must fire, so the three
	// assertions above are testing the filters and not a broken detector.
	if got := len(scanSource(t, "a.go", body)); got != 1 {
		t.Fatalf("control: got %d findings, want 1", got)
	}
}

// A file that does not parse must degrade to whatever the recovered AST
// supports, never panic and never fail the scan.
func TestUnparseableFileDegradesQuietly(t *testing.T) {
	if got := count(t, "package m\nfunc f( { this is not go"); got != 0 {
		t.Errorf("got %d findings, want 0", got)
	}
}

// Non-Go artifacts must not even be read, and the analyzer must honour
// cancellation like every other one.
func TestRespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := t.TempDir()
	p := filepath.Join(dir, "a.go")
	if err := os.WriteFile(p, []byte("package m\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Analyzer{}).ScanArtifacts(ctx,
		[]discovery.Artifact{{Path: "a.go", AbsPath: p}}); err == nil {
		t.Error("want a context error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Rule catalogue
// ---------------------------------------------------------------------------

func TestRuleIsCataloguedAtMediumSeverity(t *testing.T) {
	rs := (&Analyzer{}).Rules().Rules()
	if len(rs) != 1 {
		t.Fatalf("got %d rules, want 1", len(rs))
	}
	r := rs[0]
	if r.ID != ruleID {
		t.Errorf("ID = %q, want %q", r.ID, ruleID)
	}
	// Medium is a deliberate choice, not an oversight: the fleet gate fails on
	// net-new critical/high, and no true positive for this shape has been
	// observed in the wild yet. Promoting it is a decision with evidence
	// attached, so pin it here.
	if r.Severity != findings.SeverityMedium {
		t.Errorf("severity = %q, want medium", r.Severity)
	}
	if r.Metadata["cwe"] != "CWE-190" {
		t.Errorf("cwe = %q, want CWE-190", r.Metadata["cwe"])
	}
	if r.Remediation == "" || r.Description == "" {
		t.Error("rule must carry a description and remediation")
	}
}

// ---------------------------------------------------------------------------
// Unit-level checks on the lattice, which the rest of the analyzer rests on
// ---------------------------------------------------------------------------

func TestLossyLattice(t *testing.T) {
	k := func(n string) intKind { return intTypes[n] }
	cases := []struct {
		from, to string
		want     bool
	}{
		{"int64", "int32", true},
		{"int", "int32", true},
		{"int64", "uint64", true},  // negative becomes enormous
		{"int32", "uint64", true},  // ditto, even though it widens
		{"uint64", "int64", true},  // top half becomes negative
		{"uint32", "int32", true},  // ditto
		{"uint8", "int16", false},  // exact
		{"uint32", "int64", false}, // exact
		{"int32", "int64", false},
		{"byte", "int", false},
		{"int32", "int32", false},
		{"int32", "rune", false}, // rune IS int32
		{"uint64", "uint8", true},
	}
	for _, c := range cases {
		if _, got := lossy(k(c.from), k(c.to)); got != c.want {
			t.Errorf("lossy(%s, %s) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}

func TestParseUintLit(t *testing.T) {
	for _, c := range []struct {
		in   string
		want uint64
		ok   bool
	}{
		{"255", 255, true},
		{"0xFF", 255, true},
		{"0o777", 511, true},
		{"0777", 511, true},
		{"0b1010", 10, true},
		{"1_000", 1000, true},
		{"0x", 0, false},
		{"0b2", 0, false},
	} {
		got, ok := parseUintLit(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("parseUintLit(%q) = %d,%v; want %d,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestFitsIn(t *testing.T) {
	for _, c := range []struct {
		max  uint64
		kind string
		want bool
	}{
		{255, "uint8", true},
		{256, "uint8", false},
		{127, "int8", true},
		{128, "int8", false},
		{65535, "uint16", true},
		{65536, "uint16", false},
	} {
		if got := fitsIn(c.max, intTypes[c.kind]); got != c.want {
			t.Errorf("fitsIn(%d, %s) = %v, want %v", c.max, c.kind, got, c.want)
		}
	}
}
