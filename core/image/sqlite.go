package image

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// A read-only reader for the part of the SQLite file format that reading one
// rowid table needs (https://www.sqlite.org/fileformat.html): the database
// header, table b-tree pages (interior and leaf), overflow pages, and the
// record format. rpm's database is SQLite since EL9; nox reads it without a
// SQLite library, and nothing in it is executed.
//
// Every structural inconsistency is an error. A partly read table would be a
// short package list presented as a complete one.

var sqliteMagic = []byte("SQLite format 3\x00")

type sqliteDB struct {
	data     []byte
	pageSize int
	usable   int
	pages    int
}

func openSQLite(data []byte) (*sqliteDB, error) {
	if len(data) < 100 || !bytes.Equal(data[:16], sqliteMagic) {
		return nil, errors.New("not a SQLite database")
	}
	ps := int(binary.BigEndian.Uint16(data[16:18]))
	if ps == 1 {
		ps = 65536
	}
	if ps < 512 || ps&(ps-1) != 0 {
		return nil, fmt.Errorf("SQLite page size %d is not a power of two from 512", ps)
	}
	db := &sqliteDB{data: data, pageSize: ps, usable: ps - int(data[20])}
	if len(data)%ps != 0 {
		return nil, fmt.Errorf("SQLite file is %d bytes, not a whole number of %d-byte pages (cut short?)", len(data), ps)
	}
	db.pages = len(data) / ps
	if n := int(binary.BigEndian.Uint32(data[28:32])); n != 0 && n != db.pages {
		return nil, fmt.Errorf("SQLite header says %d pages, the file holds %d", n, db.pages)
	}
	return db, nil
}

func (db *sqliteDB) page(n int) ([]byte, error) {
	if n < 1 || n > db.pages {
		return nil, fmt.Errorf("SQLite page %d outside the file's %d pages", n, db.pages)
	}
	return db.data[(n-1)*db.pageSize : n*db.pageSize], nil
}

// tableRoot finds a table's root page in sqlite_master (page 1).
func (db *sqliteDB) tableRoot(name string) (int, error) {
	root := 0
	err := db.walkTable(1, func(rec []any) error {
		if len(rec) >= 4 && rec[0] == "table" && strings.EqualFold(fmt.Sprint(rec[1]), name) {
			n, ok := rec[3].(int64)
			if !ok {
				return fmt.Errorf("table %s has no root page", name)
			}
			root = int(n)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if root == 0 {
		return 0, fmt.Errorf("no table %s", name)
	}
	return root, nil
}

// walkTable visits every row of the table b-tree rooted at page root, in
// rowid order.
func (db *sqliteDB) walkTable(root int, visit func(rec []any) error) error {
	seen := map[int]bool{}
	var walk func(n int) error
	walk = func(n int) error {
		if seen[n] {
			return fmt.Errorf("SQLite page %d is reached twice (a cycle)", n)
		}
		seen[n] = true
		p, err := db.page(n)
		if err != nil {
			return err
		}
		hdr := 0
		if n == 1 {
			hdr = 100
		}
		if hdr+8 > len(p) {
			return fmt.Errorf("SQLite page %d is too short for a b-tree header", n)
		}
		kind := p[hdr]
		cells := int(binary.BigEndian.Uint16(p[hdr+3 : hdr+5]))
		ptrs := hdr + 8
		switch kind {
		case 0x05: // table interior
			ptrs = hdr + 12
		case 0x0d: // table leaf
		default:
			return fmt.Errorf("SQLite page %d has type %#x, not a table b-tree page", n, kind)
		}
		if ptrs+2*cells > len(p) {
			return fmt.Errorf("SQLite page %d: %d cells do not fit", n, cells)
		}
		for i := 0; i < cells; i++ {
			off := int(binary.BigEndian.Uint16(p[ptrs+2*i:]))
			if off >= len(p) {
				return fmt.Errorf("SQLite page %d: cell %d points outside the page", n, i)
			}
			if kind == 0x05 {
				if off+4 > len(p) {
					return fmt.Errorf("SQLite page %d: cell %d is cut short", n, i)
				}
				if err := walk(int(binary.BigEndian.Uint32(p[off:]))); err != nil {
					return err
				}
				continue
			}
			payload, err := db.leafPayload(p, off, n)
			if err != nil {
				return err
			}
			rec, err := decodeRecord(payload)
			if err != nil {
				return fmt.Errorf("SQLite page %d, cell %d: %w", n, i, err)
			}
			if err := visit(rec); err != nil {
				return err
			}
		}
		if kind == 0x05 {
			return walk(int(binary.BigEndian.Uint32(p[hdr+8:])))
		}
		return nil
	}
	return walk(root)
}

// leafPayload returns a table leaf cell's whole payload, following overflow
// pages.
func (db *sqliteDB) leafPayload(p []byte, off, pageNo int) ([]byte, error) {
	size, n := sqliteVarint(p[off:])
	if n == 0 {
		return nil, fmt.Errorf("SQLite page %d: unreadable cell", pageNo)
	}
	off += n
	if _, n = sqliteVarint(p[off:]); n == 0 { // rowid
		return nil, fmt.Errorf("SQLite page %d: unreadable rowid", pageNo)
	}
	off += n
	if size < 0 || size > int64(len(db.data)) {
		return nil, fmt.Errorf("SQLite page %d: payload of %d bytes", pageNo, size)
	}
	total := int(size)
	u := db.usable
	maxLocal := u - 35
	local := total
	if total > maxLocal {
		minLocal := (u-12)*32/255 - 23
		local = minLocal + (total-minLocal)%(u-4)
		if local > maxLocal {
			local = minLocal
		}
	}
	if off+local > len(p) {
		return nil, fmt.Errorf("SQLite page %d: payload runs past the page", pageNo)
	}
	out := make([]byte, 0, total)
	out = append(out, p[off:off+local]...)
	if local == total {
		return out, nil
	}
	if off+local+4 > len(p) {
		return nil, fmt.Errorf("SQLite page %d: no overflow pointer", pageNo)
	}
	next := int(binary.BigEndian.Uint32(p[off+local:]))
	seen := map[int]bool{}
	for len(out) < total {
		if next == 0 || seen[next] {
			return nil, fmt.Errorf("SQLite overflow chain from page %d ends after %d of %d bytes", pageNo, len(out), total)
		}
		seen[next] = true
		op, err := db.page(next)
		if err != nil {
			return nil, err
		}
		take := min(total-len(out), u-4)
		out = append(out, op[4:4+take]...)
		next = int(binary.BigEndian.Uint32(op[:4]))
	}
	return out, nil
}

// decodeRecord reads a SQLite record: integers as int64, text as string,
// blobs as []byte, NULL as nil. Floats are not needed here and are an error.
func decodeRecord(b []byte) ([]any, error) {
	hlen, n := sqliteVarint(b)
	if n == 0 || hlen < int64(n) || hlen > int64(len(b)) {
		return nil, errors.New("unreadable record header")
	}
	var types []int64
	for pos := n; pos < int(hlen); {
		t, m := sqliteVarint(b[pos:int(hlen)])
		if m == 0 {
			return nil, errors.New("unreadable record header")
		}
		types = append(types, t)
		pos += m
	}
	body := b[hlen:]
	out := make([]any, 0, len(types))
	for _, t := range types {
		switch {
		case t == 0:
			out = append(out, nil)
		case t >= 1 && t <= 6:
			size := []int{0, 1, 2, 3, 4, 6, 8}[t]
			if len(body) < size {
				return nil, errors.New("record is cut short")
			}
			var v int64
			for _, c := range body[:size] {
				v = v<<8 | int64(c)
			}
			if body[0]&0x80 != 0 { // sign-extend
				v -= 1 << (8 * size)
			}
			out = append(out, v)
			body = body[size:]
		case t == 8, t == 9:
			out = append(out, t-8)
		case t >= 12:
			size := int((t - 12) / 2)
			if t%2 == 1 {
				size = int((t - 13) / 2)
			}
			if len(body) < size {
				return nil, errors.New("record is cut short")
			}
			if t%2 == 0 {
				out = append(out, body[:size])
			} else {
				out = append(out, string(body[:size]))
			}
			body = body[size:]
		default:
			return nil, fmt.Errorf("record serial type %d is not read", t)
		}
	}
	return out, nil
}

// sqliteVarint reads SQLite's big-endian varint (1 to 9 bytes); n is 0 when
// b holds none.
func sqliteVarint(b []byte) (v int64, n int) {
	for i := 0; i < 9 && i < len(b); i++ {
		if i == 8 {
			return v<<8 | int64(b[i]), 9
		}
		v = v<<7 | int64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return 0, 0
}
