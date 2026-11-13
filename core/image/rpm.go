package image

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// rpm's package database. EL9 and later keep it as SQLite at
// var/lib/rpm/rpmdb.sqlite: one row per installed package in the Packages
// table, its blob an rpm header. Advisories for AlmaLinux and Rocky Linux name
// the binary package (openssl-libs), which is the header's NAME, at
// [epoch:]version-release.

const (
	rpmTagName    = 1000
	rpmTagVersion = 1001
	rpmTagRelease = 1002
	rpmTagEpoch   = 1003

	rpmTypeInt32  = 4
	rpmTypeString = 6
)

type rpmPackage struct{ name, evr string }

// readRPMDB lists the packages in an rpmdb.sqlite. gpg-pubkey rows are
// imported signing keys, not software, and are left out.
func readRPMDB(data []byte) ([]rpmPackage, error) {
	db, err := openSQLite(data)
	if err != nil {
		return nil, err
	}
	root, err := db.tableRoot("Packages")
	if err != nil {
		return nil, err
	}
	var out []rpmPackage
	err = db.walkTable(root, func(rec []any) error {
		if len(rec) < 2 {
			return errors.New("a Packages row has no blob")
		}
		blob, ok := rec[1].([]byte)
		if !ok {
			return errors.New("a Packages row's blob is not a blob")
		}
		p, err := parseRPMHeader(blob)
		if err != nil {
			return err
		}
		if p.name != "gpg-pubkey" {
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

// parseRPMHeader reads NAME, EPOCH, VERSION and RELEASE from a header blob as
// rpm stores it in its database: index count, data length, the index entries
// (tag, type, offset, count; big-endian), then the data store.
func parseRPMHeader(b []byte) (rpmPackage, error) {
	if len(b) < 8 {
		return rpmPackage{}, errors.New("rpm header is cut short")
	}
	il := int(binary.BigEndian.Uint32(b[0:4]))
	dl := int(binary.BigEndian.Uint32(b[4:8]))
	if il < 1 || il > 1<<16 || dl < 0 || 8+16*il+dl > len(b) {
		return rpmPackage{}, fmt.Errorf("rpm header claims %d entries and %d data bytes in %d", il, dl, len(b))
	}
	store := b[8+16*il : 8+16*il+dl]
	str := func(off int) (string, error) {
		if off < 0 || off >= len(store) {
			return "", errors.New("rpm header string outside its data")
		}
		end := off
		for end < len(store) && store[end] != 0 {
			end++
		}
		if end == len(store) {
			return "", errors.New("rpm header string is not terminated")
		}
		return string(store[off:end]), nil
	}
	var name, version, release, epoch string
	for i := 0; i < il; i++ {
		e := b[8+16*i:]
		tag := int(binary.BigEndian.Uint32(e[0:4]))
		typ := int(binary.BigEndian.Uint32(e[4:8]))
		off := int(binary.BigEndian.Uint32(e[8:12]))
		var err error
		switch {
		case tag == rpmTagName && typ == rpmTypeString:
			name, err = str(off)
		case tag == rpmTagVersion && typ == rpmTypeString:
			version, err = str(off)
		case tag == rpmTagRelease && typ == rpmTypeString:
			release, err = str(off)
		case tag == rpmTagEpoch && typ == rpmTypeInt32:
			if off < 0 || off+4 > len(store) {
				return rpmPackage{}, errors.New("rpm header epoch outside its data")
			}
			epoch = strconv.FormatUint(uint64(binary.BigEndian.Uint32(store[off:])), 10)
		}
		if err != nil {
			return rpmPackage{}, err
		}
	}
	if name == "" || version == "" || release == "" {
		return rpmPackage{}, fmt.Errorf("rpm header without name, version or release (%q %q %q)", name, version, release)
	}
	evr := version + "-" + release
	if epoch != "" {
		evr = epoch + ":" + evr
	}
	return rpmPackage{name: name, evr: evr}, nil
}

// rpmContents reads rpm's database when the image has one, and otherwise
// says why its packages were not listed.
func rpmContents(files map[string][]byte, osID, distro string) (pkgs []Package, notes []string) {
	const sqlitePath, bdbPath, walPath = "var/lib/rpm/rpmdb.sqlite", "var/lib/rpm/Packages", "var/lib/rpm/rpmdb.sqlite-wal"
	db, haveSQLite := files[sqlitePath]
	_, haveBDB := files[bdbPath]
	if !haveSQLite && !haveBDB {
		return nil, nil
	}
	switch {
	case osID == "rhel":
		return nil, []string{"Red Hat publishes advisories per product repository (baseos, appstream, EUS), and an image's rpm database does not record which repository a package came from, so its packages are not checked"}
	case !haveSQLite:
		return nil, []string{"rpm's Berkeley DB package database (EL8 and earlier) is not read, so its packages are not checked"}
	case distro == "":
		return nil, []string{fmt.Sprintf("the rpm packages of %q have no OSV ecosystem nox maps, so they are not checked", osID)}
	}
	if size := markerSize(files[walPath]); size > 32 { // a WAL header alone is 32 bytes
		return nil, []string{"rpm's database has an uncheckpointed write-ahead log, whose rows the database file does not hold yet, so its packages are not listed rather than listed short"}
	}
	got, err := readRPMDB(db)
	if err != nil {
		return nil, []string{fmt.Sprintf("rpm's database could not be read (%v), so its packages are not checked", err)}
	}
	for _, p := range got {
		pkgs = append(pkgs, Package{Name: p.name, Version: p.evr, Ecosystem: distro, Path: sqlitePath})
	}
	return pkgs, nil
}

func markerSize(b []byte) int64 {
	s, ok := strings.CutPrefix(string(b), markerTag)
	if !ok {
		return 0
	}
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}
