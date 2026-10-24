package git

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// maxExportedFile bounds one file extracted from a ref. A tracked file larger
// than this is not source a scanner reads, and an unbounded copy is how a
// hostile repository fills a disk.
const maxExportedFile = 256 << 20

// ExportTree writes the tree of ref into dest, an existing empty directory.
//
// It reads from the object database with `git archive`, so the user's checkout,
// index and refs are never touched: no worktree is added, nothing is checked
// out, and a dirty working tree is irrelevant. Symbolic links are not
// recreated; a link in a tree is never followed by the scanner and recreating
// one is how an extraction escapes its directory.
//
// git archive applies checkout line-ending conversion, so on a Windows
// machine with core.autocrlf (or the native core.eol) the base tree would be
// exported with CRLF while the committed bytes are LF. Pinning both settings
// exports what was committed; an explicit eol attribute in the repository's
// .gitattributes still applies, as it would for any checkout.
func ExportTree(repoRoot, ref, dest string) error {
	cmd := exec.Command("git", "-c", "core.autocrlf=false", "-c", "core.eol=lf", "archive", "--format=tar", ref)
	cmd.Dir = repoRoot
	out, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("git archive: %w", err)
	}
	var stderr limitedBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("git archive: %w", err)
	}
	extractErr := extractTar(out, dest)
	// Drain so git can exit, then collect its status: a failed archive that
	// still yielded a partial tree must be an error, not a smaller scan.
	_, _ = io.Copy(io.Discard, out)
	if waitErr := cmd.Wait(); waitErr != nil {
		return fmt.Errorf("git archive %s: %w: %s", ref, waitErr, stderr.String())
	}
	return extractErr
}

func extractTar(r io.Reader, dest string) error {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
			continue
		}
		if !filepath.IsLocal(h.Name) {
			return fmt.Errorf("archive entry %q escapes the destination", h.Name)
		}
		target := filepath.Join(dest, filepath.FromSlash(h.Name))
		if h.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := writeExported(tr, target, h); err != nil {
			return err
		}
	}
}

func writeExported(tr *tar.Reader, target string, h *tar.Header) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if h.Mode&0o111 != 0 {
		mode = 0o755
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode) //nolint:gosec // target is joined from a validated local path under dest
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(tr, maxExportedFile+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxExportedFile {
		return fmt.Errorf("archive entry %q exceeds %d bytes", h.Name, int64(maxExportedFile))
	}
	return nil
}

// limitedBuffer keeps the first few KiB of stderr for an error message.
type limitedBuffer struct{ b []byte }

func (l *limitedBuffer) Write(p []byte) (int, error) {
	const keep = 4096
	if room := keep - len(l.b); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		l.b = append(l.b, p[:room]...)
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string { return string(l.b) }
