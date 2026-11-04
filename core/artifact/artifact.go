// Package artifact opens a built artifact (a release archive or a single
// file) as a directory nox can scan, and identifies it by its SHA-256.
//
// It exists so nox can describe what it ships: a release SBOM is about the
// archive users download, not the source tree it was built from. Extraction
// is defensive because an archive is untrusted input: entries that would land
// outside the target, absolute paths and links are refused, and the expanded
// size and file count are bounded. A refused or over-budget archive fails as a
// whole; an SBOM of a partly read archive would understate it.
package artifact

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Artifact is an opened artifact.
type Artifact struct {
	// Name is the artifact's file name.
	Name string
	// SHA256 is the hex digest of the artifact file as given.
	SHA256 string
	// Dir holds its contents: the extracted archive, or the single file.
	Dir string
}

type limits struct {
	maxBytes int64
	maxFiles int
}

// defaultLimits bounds what one artifact may expand to. nox's own release
// archives are about 60 MB expanded with three files.
var defaultLimits = limits{maxBytes: 2 << 30, maxFiles: 100_000}

// Open opens the artifact at src into dest, an empty directory the caller
// owns and removes. Archives (.tar.gz, .tgz, .tar, .zip) are extracted; any
// other file is copied in as is.
func Open(src, dest string) (Artifact, error) {
	return open(src, dest, defaultLimits)
}

func open(src, dest string, lim limits) (Artifact, error) {
	sum, err := fileSHA256(src)
	if err != nil {
		return Artifact{}, err
	}
	a := Artifact{Name: filepath.Base(src), SHA256: sum, Dir: dest}
	x := &extractor{dest: dest, lim: lim}
	lower := strings.ToLower(a.Name)
	switch {
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		err = x.tarFile(src, true)
	case strings.HasSuffix(lower, ".tar"):
		err = x.tarFile(src, false)
	case strings.HasSuffix(lower, ".zip"):
		err = x.zipFile(src)
	default:
		var f *os.File
		if f, err = os.Open(src); err == nil {
			err = x.write(a.Name, f, 0o755)
			_ = f.Close()
		}
	}
	if err != nil {
		return Artifact{}, fmt.Errorf("%s: %w", a.Name, err)
	}
	return a, nil
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }() // read-only
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type extractor struct {
	dest  string
	lim   limits
	bytes int64
	files int
}

var errBudget = errors.New("expands beyond the extraction budget")

// target resolves an entry name inside dest, refusing one that escapes it.
func (x *extractor) target(name string) (string, error) {
	clean := path.Clean(strings.ReplaceAll(name, `\`, "/"))
	if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") || filepath.VolumeName(clean) != "" {
		return "", fmt.Errorf("entry %q leaves the archive", name)
	}
	return filepath.Join(x.dest, filepath.FromSlash(clean)), nil
}

// write copies one regular file into dest within the budget.
func (x *extractor) write(name string, r io.Reader, mode os.FileMode) error {
	p, err := x.target(name)
	if err != nil {
		return err
	}
	x.files++
	if x.files > x.lim.maxFiles {
		return errBudget
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode.Perm()|0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(r, x.lim.maxBytes-x.bytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if x.bytes += n; x.bytes > x.lim.maxBytes {
		return errBudget
	}
	return nil
}

func (x *extractor) tarFile(src string, gz bool) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // read-only
	var r io.Reader = f
	if gz {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer func() { _ = zr.Close() }()
		r = zr
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if _, err := x.target(h.Name); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := x.write(h.Name, tr, os.FileMode(h.Mode)); err != nil {
				return err
			}
		default:
			return fmt.Errorf("entry %q is a link or special file, which is not read", h.Name)
		}
	}
}

func (x *extractor) zipFile(src string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer func() { _ = zr.Close() }()
	for _, zf := range zr.File {
		mode := zf.Mode()
		switch {
		case mode.IsDir():
			if _, err := x.target(zf.Name); err != nil {
				return err
			}
			continue
		case !mode.IsRegular():
			return fmt.Errorf("entry %q is a link or special file, which is not read", zf.Name)
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		err = x.write(zf.Name, rc, mode)
		_ = rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
