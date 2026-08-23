package source

import "testing"

func TestParseGoFileTolerantAndRealFilename(t *testing.T) {
	file, fset := ParseGoFile("pkg/x.go", []byte("package x\nfunc F(){}\n"))
	if file == nil {
		t.Fatal("valid Go should parse")
	}
	// The real path reaches the position metadata, not a hardcoded "src.go".
	if got := fset.Position(file.Pos()).Filename; got != "pkg/x.go" {
		t.Errorf("filename = %q, want pkg/x.go", got)
	}
	// A non-compiling file returns a recovered partial AST, never a crash.
	partial, _ := ParseGoFile("bad.go", []byte("package x\nfunc F(){ this is not go "))
	if partial == nil {
		t.Error("a partial AST should be recovered from a non-compiling file")
	}
}

func TestImportAliases(t *testing.T) {
	src := `package x
import (
	"crypto/rand"
	mr "math/rand"
	rv2 "math/rand/v2"
	_ "embed"
)
`
	file, _ := ParseGoFile("x.go", []byte(src))

	// crypto/rand under its default name.
	if a := ImportAliases(file, "crypto/rand"); !a["rand"] {
		t.Errorf("crypto/rand should bind name 'rand', got %v", a)
	}
	// math/rand under an explicit alias.
	if a := ImportAliases(file, "math/rand"); !a["mr"] || a["rand"] {
		t.Errorf("aliased math/rand should bind 'mr' only, got %v", a)
	}
	// math/rand/v2 under an explicit alias.
	if a := ImportAliases(file, "math/rand/v2"); !a["rv2"] {
		t.Errorf("math/rand/v2 should bind 'rv2', got %v", a)
	}
	// A blank import binds no name.
	if a := ImportAliases(file, "embed"); len(a) != 0 {
		t.Errorf("blank import should bind no name, got %v", a)
	}
	if len(ImportAliases(nil, "x")) != 0 {
		t.Error("nil file must yield no aliases")
	}
}

// The Go /vN convention: a versioned module's default package name is the
// element before /vN, not "vN".
func TestDefaultPackageNameHandlesMajorVersion(t *testing.T) {
	src := `package x
import "math/rand/v2"
`
	file, _ := ParseGoFile("x.go", []byte(src))
	if a := ImportAliases(file, "math/rand/v2"); !a["rand"] {
		t.Errorf("math/rand/v2 default name should be 'rand' (not 'v2'), got %v", a)
	}
}
