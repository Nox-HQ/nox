package image

import (
	"context"
	"os"
	"strings"
	"testing"
)

func rpmFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/rpmdb/rpmdb.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rpm's sqlite database (EL9 and later), read without a SQLite library:
// every row of the Packages table, across interior b-tree pages and
// overflow pages, decoded as an rpm header. gpg-pubkey entries are keys,
// not software.
func TestRPMDBIsRead(t *testing.T) {
	got, err := readRPMDB(rpmFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 152 {
		t.Errorf("%d packages, want 152 (153 rows less one gpg-pubkey)", len(got))
	}
	have := map[string]string{}
	for _, p := range got {
		have[p.name] = p.evr
	}
	for name, evr := range map[string]string{
		"openssl-libs": "1:3.0.1-41.el9_0", // epoch, and a header on overflow pages
		"glibc":        "2.34-100.el9_4.2", // no epoch
		"pkg000":       "1.0-1.el9",
		"pkg149":       "1.149-1.el9", // the last row, past interior pages
	} {
		if have[name] != evr {
			t.Errorf("%s = %q, want %q", name, have[name], evr)
		}
	}
	if _, ok := have["gpg-pubkey"]; ok {
		t.Error("a gpg-pubkey entry was reported as a package")
	}
}

// A database that is not one, or is cut short, is an error, never a short
// list read as complete.
func TestRPMDBDamageIsAnError(t *testing.T) {
	b := rpmFixture(t)
	for name, data := range map[string][]byte{
		"not sqlite": []byte(strings.Repeat("x", 4096)),
		"truncated":  b[:len(b)/2],
		"empty":      nil,
	} {
		if pkgs, err := readRPMDB(data); err == nil {
			t.Errorf("%s: no error, %d packages", name, len(pkgs))
		}
	}
}

const almaRelease = "NAME=\"AlmaLinux\"\nVERSION=\"9.4 (Seafoam Ocelot)\"\nID=\"almalinux\"\nVERSION_ID=\"9.4\"\n"

func TestAlmaLinuxImageContents(t *testing.T) {
	reg := newRegistry(t)
	digest := reg.image(t, layer(t, file{name: "etc/os-release", body: almaRelease},
		file{name: "var/lib/rpm/rpmdb.sqlite", body: string(rpmFixture(t))}))
	got, err := reg.client(t).Contents(context.Background(), "golang", digest)
	if err != nil {
		t.Fatal(err)
	}
	if got.Distro != "almalinux:9" || len(got.Packages) != 152 {
		t.Fatalf("distro %q, %d packages; notes %v", got.Distro, len(got.Packages), got.Notes)
	}
	if p := got.Packages[0]; p.Ecosystem != "almalinux:9" || p.Path != "var/lib/rpm/rpmdb.sqlite" {
		t.Errorf("first package %+v", p)
	}
}

// What nox cannot answer for is named, not listed as clean.
func TestRPMImagesNotReadSayWhy(t *testing.T) {
	for name, tc := range map[string]struct {
		files []file
		note  string
	}{
		"red hat": {[]file{{name: "etc/os-release", body: "ID=\"rhel\"\nVERSION_ID=\"9.4\"\n"},
			{name: "var/lib/rpm/rpmdb.sqlite", body: string(rpmFixture(t))}}, "repository"},
		"berkeley db": {[]file{{name: "etc/os-release", body: "ID=\"rocky\"\nVERSION_ID=\"8.10\"\n"},
			{name: "var/lib/rpm/Packages", body: "bdb"}}, "Berkeley DB"},
		"uncheckpointed wal": {[]file{{name: "etc/os-release", body: almaRelease},
			{name: "var/lib/rpm/rpmdb.sqlite", body: string(rpmFixture(t))},
			{name: "var/lib/rpm/rpmdb.sqlite-wal", body: strings.Repeat("w", 4096)}}, "write-ahead log"},
	} {
		t.Run(name, func(t *testing.T) {
			reg := newRegistry(t)
			got, err := reg.client(t).Contents(context.Background(), "golang", reg.image(t, layer(t, tc.files...)))
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Packages) != 0 || !strings.Contains(strings.Join(got.Notes, "|"), tc.note) {
				t.Errorf("%d packages, notes %v; want none and a note naming %q", len(got.Packages), got.Notes, tc.note)
			}
		})
	}
}
