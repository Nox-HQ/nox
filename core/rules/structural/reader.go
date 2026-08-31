package structural

import "io"

// byteReader is an io.Reader over a byte slice.
//
// bytes.NewReader would do this; it is spelled out here only so this package
// depends on nothing but yaml.v3 and the standard library's io contract, which
// keeps the parse path free of anything that could allocate a copy of a
// multi-megabyte template.
type byteReader struct {
	b   []byte
	off int
}

func newByteReader(b []byte) *byteReader { return &byteReader{b: b} }

func (r *byteReader) Read(p []byte) (int, error) {
	if r.off >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.off:])
	r.off += n
	return n, nil
}

// isEOF reports whether err ends a decode stream normally.
func isEOF(err error) bool { return err == io.EOF }
