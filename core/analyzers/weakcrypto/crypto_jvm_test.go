package weakcrypto

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

func javaMethod(body string) string {
	return "class C {\n  void run(String input) throws Exception {\n" + body + "\n  }\n}\n"
}

// The weak forms the literal pattern does not list, and algorithms held in a
// name. Each vulnerable case names the algorithm it must report.
func TestJVMWeakFormsAndNamedAlgorithms(t *testing.T) {
	vulnerable := []struct{ name, body, algo string }{
		{"MD2", `MessageDigest md = MessageDigest.getInstance("MD2");`, "MD2"},
		{"bare SHA alias", `MessageDigest md = MessageDigest.getInstance("SHA");`, "SHA-1"},
		{"bare AES is ECB", `Cipher c = Cipher.getInstance("AES");`, "ECB"},
		{"Blowfish", `Cipher c = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");`, "Blowfish"},
		{"DES key generator", `KeyGenerator kg = KeyGenerator.getInstance("DES");`, "DES"},
		{"PBE MD5 DES", `SecretKeyFactory f = SecretKeyFactory.getInstance("PBEWithMD5AndDES");`, "MD5"},
		{"MD5withRSA", `Signature s = Signature.getInstance("MD5withRSA");`, "MD5"},
		{"Commons Codec md5Hex", `String h = DigestUtils.md5Hex(input);`, "MD5"},
		{"Commons Codec sha1", `byte[] h = org.apache.commons.codec.digest.DigestUtils.sha1(input);`, "SHA-1"},
		{"Guava md5", `HashCode h = Hashing.md5().hashString(input, UTF_8);`, "MD5"},
		{"local constant", "String alg = \"DES/CBC/PKCS5Padding\";\n    Cipher c = Cipher.getInstance(alg);", "DES"},
		{"local constant digest", "final String a = \"MD5\";\n    MessageDigest md = MessageDigest.getInstance(a);", "MD5"},
	}
	for _, tt := range vulnerable {
		t.Run(tt.name, func(t *testing.T) {
			got := algorithmsFor(t, "C.java", javaMethod(tt.body))
			if len(got) != 1 || got[0] != tt.algo {
				t.Errorf("want [%s]; got %v", tt.algo, got)
			}
		})
	}
	clean := []struct{ name, body string }{
		{"AES GCM", `Cipher c = Cipher.getInstance("AES/GCM/NoPadding");`},
		{"AES CBC", `Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");`},
		{"RSA OAEP", `Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");`},
		{"SHA-256", `MessageDigest md = MessageDigest.getInstance("SHA-256");`},
		{"SHA-512 provider", `MessageDigest md = MessageDigest.getInstance("SHA-512", "SUN");`},
		{"SHA256withRSA", `Signature s = Signature.getInstance("SHA256withRSA");`},
		{"AES key generator", `KeyGenerator kg = KeyGenerator.getInstance("AES");`},
		{"DigestUtils sha256", `String h = DigestUtils.sha256Hex(input);`},
		// A name assigned twice is unknown: which value reaches the call is
		// not decided here.
		{"reassigned name", "String alg = \"AES/GCM/NoPadding\";\n    if (input.isEmpty()) alg = \"DES\";\n    Cipher c = Cipher.getInstance(alg);"},
		{"name from a parameter", `Cipher c = Cipher.getInstance(input);`},
		{"commented out", `// Cipher c = Cipher.getInstance("AES");`},
	}
	for _, tt := range clean {
		t.Run("clean "+tt.name, func(t *testing.T) {
			if got := algorithmsFor(t, "C.java", javaMethod(tt.body)); len(got) != 0 {
				t.Errorf("want no finding; got %v", got)
			}
		})
	}
}

// A class constant is the commonest named form, in Java and Kotlin.
func TestJVMClassConstant(t *testing.T) {
	java := "class C {\n  private static final String ALGORITHM = \"DESede/CBC/PKCS5Padding\";\n" +
		"  void run() throws Exception {\n    Cipher c = Cipher.getInstance(ALGORITHM);\n  }\n}\n"
	if got := algorithmsFor(t, "C.java", java); len(got) != 1 || got[0] != "3DES" {
		t.Errorf("Java constant: want [3DES]; got %v", got)
	}
	kotlin := "private const val ALGORITHM = \"MD5\"\nfun h(b: ByteArray) = MessageDigest.getInstance(ALGORITHM).digest(b)\n"
	if got := algorithmsFor(t, "C.kt", kotlin); len(got) != 1 || got[0] != "MD5" {
		t.Errorf("Kotlin constant: want [MD5]; got %v", got)
	}
}

// scanWithFiles scans a set of files together, so a .properties file is seen
// beside the source that reads it.
func scanWithFiles(t *testing.T, files map[string]string) []string {
	t.Helper()
	dir := t.TempDir()
	var arts []discovery.Artifact
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		arts = append(arts, discovery.Artifact{Path: name, AbsPath: p})
	}
	fs, err := (&Analyzer{}).ScanArtifacts(context.Background(), arts)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range fs.Findings() {
		got = append(got, f.Metadata["algorithm"])
	}
	sort.Strings(got)
	return got
}

// A configured algorithm is decided by the project's properties: the key's
// value when a file defines it, the literal fallback only when the scan saw
// the project's properties and none defines the key, and nothing when the
// scan saw no properties at all (a root below the resources).
func TestJVMConfiguredAlgorithm(t *testing.T) {
	src := javaMethod("java.util.Properties p = new java.util.Properties();\n" +
		"    String alg = p.getProperty(\"cipher\", \"AES/ECB/PKCS5Padding\");\n" +
		"    Cipher c = Cipher.getInstance(alg);")
	cases := []struct {
		name  string
		props map[string]string
		want  []string
	}{
		{"key defined strong overrides weak fallback", map[string]string{"src/main/resources/app.properties": "cipher=AES/GCM/NoPadding\n"}, nil},
		{"key defined weak", map[string]string{"src/main/resources/app.properties": "# crypto\ncipher = DES/CBC/PKCS5Padding\n"}, []string{"DES"}},
		{"key undefined uses fallback", map[string]string{"src/main/resources/app.properties": "other=1\n"}, []string{"ECB"}},
		{"conflicting definitions are unknown, even both weak", map[string]string{
			"a/app.properties": "cipher=DES\n",
			"b/app.properties": "cipher=RC4\n",
		}, nil},
		{"no properties seen", nil, nil},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"src/main/java/C.java": src}
			for k, v := range tt.props {
				files[k] = v
			}
			got := scanWithFiles(t, files)
			if len(got) != len(tt.want) || (len(got) > 0 && got[0] != tt.want[0]) {
				t.Errorf("want %v; got %v", tt.want, got)
			}
		})
	}
	// Without a fallback, only a defining file decides.
	noFallback := javaMethod("String alg = props.getProperty(\"hashAlg\");\n    MessageDigest md = MessageDigest.getInstance(alg);")
	got := scanWithFiles(t, map[string]string{"C.java": noFallback, "benchmark.properties": "hashAlg=SHA1\n"})
	if len(got) != 1 || got[0] != "SHA-1" {
		t.Errorf("configured without fallback: want [SHA-1]; got %v", got)
	}
}
