package deps

import (
	"bufio"
	"io"
)

// newLineScanner returns a line scanner that does not stop at bufio.Scanner's
// 64 KiB default.
//
// The default is the problem this package already documented at
// maxLockfileLine: a line over the limit ends iteration, and a caller that does
// not check Err() simply returns what it had. A truncated dependency list is
// indistinguishable from a complete one, so everything after the long line is
// missing from the SBOM and from vulnerability matching with nothing to say so.
//
// Long lines in real manifests are ordinary — pnpm peer-dependency keys, yarn
// integrity hashes, a vendored one-line JSON blob, a Dockerfile with one
// enormous RUN. Use this for every line-oriented parse in the package;
// TestEveryLineScannerRaisesTheLimit enforces that.
func newLineScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLockfileLine)
	return sc
}
