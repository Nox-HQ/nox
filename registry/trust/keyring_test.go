package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func testKeyPair(t *testing.T) (ed25519.PublicKey, []byte) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return pub, ExportKeyPEM(pub)
}

func TestNewKey(t *testing.T) {
	pub, pemData := testKeyPair(t)

	k, err := NewKey("test-signer", pemData)
	if err != nil {
		t.Fatalf("NewKey() error = %v", err)
	}
	if k.Name != "test-signer" {
		t.Errorf("Name = %q, want %q", k.Name, "test-signer")
	}
	if k.Fingerprint != KeyFingerprint(pub) {
		t.Errorf("Fingerprint mismatch")
	}
	if k.PublicKeyPEM != string(pemData) {
		t.Error("PublicKeyPEM mismatch")
	}
}

func TestNewKeyInvalidPEM(t *testing.T) {
	_, err := NewKey("bad", []byte("not valid pem"))
	if err == nil {
		t.Error("NewKey() expected error for invalid PEM")
	}
}

func TestKeyFingerprintDeterministic(t *testing.T) {
	pub, _ := testKeyPair(t)
	fp1 := KeyFingerprint(pub)
	fp2 := KeyFingerprint(pub)
	if fp1 != fp2 {
		t.Errorf("non-deterministic fingerprint: %q != %q", fp1, fp2)
	}
}

func TestKeyringAddFindRemove(t *testing.T) {
	kr := NewKeyring()
	_, pem1 := testKeyPair(t)
	_, pem2 := testKeyPair(t)

	k1, err := NewKey("signer-1", pem1)
	if err != nil {
		t.Fatalf("NewKey(1) error = %v", err)
	}
	k2, err := NewKey("signer-2", pem2)
	if err != nil {
		t.Fatalf("NewKey(2) error = %v", err)
	}

	kr.Add(k1)
	kr.Add(k2)
	if len(kr.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(kr.Keys))
	}

	// Find existing.
	found := kr.Find(k1.Fingerprint)
	if found == nil {
		t.Fatal("Find(k1) returned nil")
	}
	if found.Name != "signer-1" {
		t.Errorf("found name = %q, want %q", found.Name, "signer-1")
	}

	// Find non-existing.
	if kr.Find("nonexistent") != nil {
		t.Error("Find(nonexistent) should return nil")
	}

	// Remove existing.
	if err := kr.Remove(k1.Fingerprint); err != nil {
		t.Fatalf("Remove(k1) error = %v", err)
	}
	if len(kr.Keys) != 1 {
		t.Fatalf("expected 1 key after removal, got %d", len(kr.Keys))
	}
	if kr.Find(k1.Fingerprint) != nil {
		t.Error("k1 should not be found after removal")
	}

	// Remove non-existing.
	if err := kr.Remove("nonexistent"); err == nil {
		t.Error("Remove(nonexistent) should return error")
	}
}

func TestKeyringDuplicateAdd(t *testing.T) {
	kr := NewKeyring()
	_, pemData := testKeyPair(t)
	k, _ := NewKey("signer", pemData)

	kr.Add(k)
	kr.Add(k) // duplicate
	if len(kr.Keys) != 1 {
		t.Errorf("expected 1 key after duplicate add, got %d", len(kr.Keys))
	}
}

func TestLoadKeyringMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent", "keyring.json")

	kr, err := LoadKeyring(path)
	if err != nil {
		t.Fatalf("LoadKeyring(missing) error = %v", err)
	}
	if len(kr.Keys) != 0 {
		t.Errorf("expected empty keyring, got %d keys", len(kr.Keys))
	}
}

func TestLoadSaveKeyringRoundTrip(t *testing.T) {
	dir := t.TempDir()
	// Resolve symlinks for macOS /var/folders → /private/var/folders.
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	path := filepath.Join(dir, "trust", "keyring.json")

	_, pem1 := testKeyPair(t)
	_, pem2 := testKeyPair(t)
	k1, _ := NewKey("alice", pem1)
	k2, _ := NewKey("bob", pem2)

	kr := NewKeyring()
	kr.Add(k1)
	kr.Add(k2)

	if err := SaveKeyring(path, kr); err != nil {
		t.Fatalf("SaveKeyring() error = %v", err)
	}

	loaded, err := LoadKeyring(path)
	if err != nil {
		t.Fatalf("LoadKeyring() error = %v", err)
	}
	if len(loaded.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(loaded.Keys))
	}
	if loaded.Keys[0].Name != "alice" || loaded.Keys[1].Name != "bob" {
		t.Errorf("key names mismatch: got %q, %q", loaded.Keys[0].Name, loaded.Keys[1].Name)
	}
}

func TestLoadKeyringInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{invalid json"), 0o644); err != nil {
		t.Fatalf("writing bad file: %v", err)
	}

	_, err := LoadKeyring(path)
	if err == nil {
		t.Error("LoadKeyring(invalid JSON) should return error")
	}
}

func TestSaveKeyringCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	dir, _ = filepath.EvalSymlinks(dir)
	path := filepath.Join(dir, "nested", "deep", "keyring.json")

	kr := NewKeyring()
	if err := SaveKeyring(path, kr); err != nil {
		t.Fatalf("SaveKeyring() error = %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

func TestSaveKeyringAtomic(t *testing.T) {
	dir := t.TempDir()
	dir, _ = filepath.EvalSymlinks(dir)
	path := filepath.Join(dir, "keyring.json")

	kr := NewKeyring()
	_, pemData := testKeyPair(t)
	k, _ := NewKey("signer", pemData)
	kr.Add(k)

	if err := SaveKeyring(path, kr); err != nil {
		t.Fatalf("SaveKeyring() error = %v", err)
	}

	// Verify no temp file left behind.
	tmp := path + ".tmp"
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("temp file should not exist after successful save")
	}
}

func TestExportKeyPEM(t *testing.T) {
	pub, _ := testKeyPair(t)
	pemData := ExportKeyPEM(pub)

	parsed, err := ParsePublicKey(pemData)
	if err != nil {
		t.Fatalf("ParsePublicKey(exported) error = %v", err)
	}
	if !pub.Equal(parsed) {
		t.Error("exported and re-parsed key do not match")
	}
}
