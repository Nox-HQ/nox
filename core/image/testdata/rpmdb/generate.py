"""Writes rpmdb.sqlite: rpm's sqlite schema with synthetic package headers.

Run with python3 -I generate.py. The output is committed; this script says
how it was made. Rows are numerous enough, at a 1024-byte page, to need
interior b-tree pages, and a few headers are large enough to spill onto
overflow pages, so the reader is exercised on both.
"""
import sqlite3, struct, os

RPM_INT32, RPM_STRING = 4, 6
NAME, VERSION, RELEASE, EPOCH, ARCH = 1000, 1001, 1002, 1003, 1022


def header(name, version, release, epoch=None, pad=0):
    entries, data = [], b""
    def add(tag, typ, value):
        nonlocal data
        if typ == RPM_INT32:
            while len(data) % 4:
                data += b"\0"
            entries.append((tag, typ, len(data), 1))
            data += struct.pack(">i", value)
        else:
            entries.append((tag, typ, len(data), 1))
            data += value.encode() + b"\0"
    add(NAME, RPM_STRING, name)
    add(VERSION, RPM_STRING, version)
    add(RELEASE, RPM_STRING, release)
    add(ARCH, RPM_STRING, "x86_64")
    if epoch is not None:
        add(EPOCH, RPM_INT32, epoch)
    if pad:
        add(5000, RPM_STRING, "x" * pad)  # stands in for file lists
    out = struct.pack(">ii", len(entries), len(data))
    for e in entries:
        out += struct.pack(">iiii", *e)
    return out + data


def main():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rpmdb.sqlite")
    if os.path.exists(path):
        os.remove(path)
    db = sqlite3.connect(path)
    db.execute("PRAGMA page_size=1024")
    db.execute("PRAGMA journal_mode=DELETE")
    db.execute("CREATE TABLE 'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)")
    db.execute("CREATE TABLE 'Name' (key TEXT NOT NULL, hnum INTEGER NOT NULL, idx INTEGER NOT NULL, PRIMARY KEY(key, hnum, idx)) WITHOUT ROWID")
    rows = [header("openssl-libs", "3.0.1", "41.el9_0", epoch=1, pad=6000),
            header("glibc", "2.34", "100.el9_4.2", pad=3000),
            header("gpg-pubkey", "8483c65d", "5ccc5b19")]
    rows += [header(f"pkg{i:03d}", f"1.{i}", "1.el9") for i in range(150)]
    for r in rows:
        db.execute("INSERT INTO Packages (blob) VALUES (?)", (r,))
    db.commit()
    db.execute("VACUUM")
    db.close()


if __name__ == "__main__":
    main()
