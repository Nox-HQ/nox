package weakcrypto

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/source"

	"github.com/nox-hq/nox/core/discovery"
)

func scanSource(t *testing.T, name, content string) int {
	t.Helper()
	return len(scanLines(t, name, content))
}

// scanLines returns the 1-based line numbers that reported a finding, so a test
// can assert *which* call shapes fired rather than only how many did.
func scanLines(t *testing.T, name, content string) []int {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	fs, err := (&Analyzer{}).ScanArtifacts(context.Background(),
		[]discovery.Artifact{{Path: name, AbsPath: p}})
	if err != nil {
		t.Fatal(err)
	}
	var lines []int
	for _, f := range fs.Findings() {
		lines = append(lines, f.Location.StartLine)
	}
	sort.Ints(lines)
	return lines
}

// algorithmsFor returns the algorithm names reported for a source, so the
// message and the `algorithm` metadata can be asserted rather than assumed.
func algorithmsFor(t *testing.T, name, content string) []string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	fs, err := (&Analyzer{}).ScanArtifacts(context.Background(),
		[]discovery.Artifact{{Path: name, AbsPath: p}})
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

// A digest has two call shapes and both must fire. CRYPTO-001 originally
// matched only the CONSTRUCTOR (md5.New()) and missed the one-shot
// (md5.Sum(b)) — which is the *more* idiomatic of the two, so the commoner
// usage was the unreported one. Both shapes are asserted in one file so they
// cannot drift apart again. (#402)
func TestFlagsBothConstructorAndOneShot(t *testing.T) {
	src := strings.Join([]string{
		"package m", // 1
		"func a(b []byte) [16]byte { return md5.Sum(b) }",  // 2 one-shot
		"func b() { _ = md5.New() }",                       // 3 constructor
		"func c(b []byte) [20]byte { return sha1.Sum(b) }", // 4 one-shot
		"func d() { _ = sha1.New() }",                      // 5 constructor
	}, "\n")
	want := []int{2, 3, 4, 5}
	got := scanLines(t, "a.go", src)
	if len(got) != len(want) {
		t.Fatalf("lines = %v, want %v — a call shape is unreported", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("lines = %v, want %v", got, want)
		}
	}
}

// The same split exists outside Go: OpenSSL in C has both MD5_Init/Update/Final
// and the one-shot MD5(), and .NET has both MD5.Create() and MD5.HashData().
func TestFlagsBothCallShapesInCAndCSharp(t *testing.T) {
	cSrc := "void a(void) {\n  MD5_Init(&ctx);\n  MD5(data, len, out);\n}"
	if got := scanLines(t, "a.c", cSrc); len(got) != 2 {
		t.Errorf("c: lines = %v, want both MD5_Init and MD5()", got)
	}
	csSrc := "class A {\n  void B() {\n    var a = MD5.Create();\n    var b = MD5.HashData(x);\n  }\n}"
	if got := scanLines(t, "A.cs", csSrc); len(got) != 2 {
		t.Errorf("csharp: lines = %v, want both MD5.Create and MD5.HashData", got)
	}
}

// positives is one entry per language, covering the primitive families that
// language actually exposes. Every line here was run through the scanner before
// being asserted.
var positives = map[string][]string{
	"a.go": {
		"h := md5.New()",
		"d := md5.Sum(b)",
		"h := sha1.New()",
		"d := sha1.Sum(b)",
		"c, _ := des.NewCipher(k)",
		"c, _ := des.NewTripleDESCipher(k)",
		"c, _ := rc4.NewCipher(k)",
	},
	"a.py": {
		"d = hashlib.md5(b'x')",
		"d = hashlib.sha1(b'x')",
		`d = hashlib.new("md5", b'x')`,
		"d = hashlib.new('sha-1')",
		"c = DES.new(key, DES.MODE_ECB)",
		"c = DES3.new(key, DES3.MODE_CBC, iv)",
		"c = ARC4.new(key)",
		"c = Cipher(algorithms.AES(key), modes.ECB())",
		"a = algorithms.TripleDES(key)",
	},
	"a.js": {
		"const h = crypto.createHash('md5')",
		`const h = crypto.createHash("sha1")`,
		"const c = crypto.createCipheriv('des-ede3-cbc', k, iv)",
		`const c = crypto.createDecipheriv("aes-128-ecb", k, iv)`,
		"const c = crypto.createCipheriv('rc4', k, '')",
		"const d = CryptoJS.MD5(x)",
		"const d = CryptoJS.TripleDES.encrypt(x, k)",
	},
	"a.ts": {
		"const h = crypto.createHash('md5')",
		"const c = crypto.createCipheriv('des-ede3-cbc', k, iv)",
	},
	"A.java": {
		`MessageDigest md = MessageDigest.getInstance("MD5");`,
		`MessageDigest md = MessageDigest.getInstance("SHA-1");`,
		`MessageDigest md = MessageDigest.getInstance("SHA1");`,
		`Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");`,
		`Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");`,
		`Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");`,
		`Signature s = Signature.getInstance("SHA1withRSA");`,
	},
	"A.kt": {
		`val md = MessageDigest.getInstance("MD5")`,
		`val c = Cipher.getInstance("AES/ECB/NoPadding")`,
	},
	"a.php": {
		"$a = mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);",
		"$b = MCRYPT_3DES;",
		"$c = openssl_encrypt($data, 'des-ecb', $key);",
		`$d = openssl_decrypt($data, "aes-128-ecb", $key);`,
		"$e = openssl_encrypt($data, 'rc4', $key);",
		"$f = openssl_digest($data, 'md5');",
	},
	"a.rb": {
		"a = Digest::MD5.hexdigest(x)",
		"a = Digest::SHA1.hexdigest(x)",
		"a = OpenSSL::Digest::MD5.new",
		"a = OpenSSL::Digest.new('md5')",
		"a = OpenSSL::Cipher::DES.new",
		"a = OpenSSL::Cipher.new('DES-EDE3-CBC')",
		`a = OpenSSL::Cipher.new("aes-128-ecb")`,
		"a = OpenSSL::Cipher::AES.new(256, :ECB)",
	},
	"A.cs": {
		"var a = MD5.Create();",
		"var a = SHA1.Create();",
		"var a = MD5.HashData(bytes);",
		"var a = new DESCryptoServiceProvider();",
		"var a = new TripleDESCryptoServiceProvider();",
		"var a = new SHA1Managed();",
		"aes.Mode = CipherMode.ECB;",
		`var a = HashAlgorithm.Create("MD5");`,
	},
	"a.rs": {
		`let d = md5::compute(b"x");`,
		"let mut h = Md5::new();",
		"let mut h = Sha1::new();",
		"let c = Des::new(&key);",
		"let c = TdesEde3::new(&key);",
		"let c = Rc4::new(&key);",
		"let e: ecb::Encryptor<Aes128> = enc;",
	},
	"a.c": {
		"MD5_Init(&ctx);",
		"MD5_Update(&ctx, d, n);",
		"MD5_Final(out, &ctx);",
		"MD5(data, len, out);",
		"SHA1(data, len, out);",
		"SHA1_Init(&s);",
		"const EVP_MD *m = EVP_md5();",
		"const EVP_MD *m = EVP_sha1();",
		"const EVP_CIPHER *c = EVP_des_ede3_cbc();",
		"const EVP_CIPHER *c = EVP_aes_128_ecb();",
		"const EVP_CIPHER *c = EVP_rc4();",
		"DES_set_key(&k, &s);",
		"DES_ecb_encrypt(in, out, &s, DES_ENCRYPT);",
		"RC4_set_key(&rk, 16, key);",
	},
	"a.cpp": {
		"MD5_Init(&ctx);",
		"SHA1(data, len, out);",
	},
	"a.m": {
		"CC_MD5(data, len, out);",
		"CC_SHA1(data, len, out);",
		"CCCrypt(kCCEncrypt, kCCAlgorithmDES, kCCOptionECBMode, key, 8, NULL, in, n, out, n, &moved);",
	},
	"a.swift": {
		"let d = Insecure.MD5.hash(data: data)",
		"let d = Insecure.SHA1.hash(data: data)",
		"CC_MD5(bytes, len, &digest)",
		"let alg = kCCAlgorithm3DES",
		"let opt = kCCOptionECBMode",
	},
	"a.sh": {
		"openssl enc -des-ecb -in a -out b",
		"openssl enc -rc4 -in a -out b",
		"openssl enc -aes-128-ecb -in a -out b",
		"openssl des3 -in a -out b",
	},
}

func TestFlagsBrokenPrimitives(t *testing.T) {
	for name, srcs := range positives {
		for _, src := range srcs {
			if n := scanSource(t, name, src); n != 1 {
				t.Errorf("%s: got %d findings, want 1 for %q", name, n, src)
			}
		}
	}
}

// negatives is the counterpart corpus: strong primitives, the algorithm named
// in a comment, an identifier named after the algorithm, and a legitimate
// non-crypto checksum. None of these may fire — a rule that flags them is a
// rule that gets globally suppressed.
var negatives = map[string][]string{
	"a.go": {
		"// we used to use md5 here, now sha256",
		"var md5sum string",
		`var sha1Digest = "sha1"`,
		"return sha256.Sum256(b)",
		"h := sha256.New()",
		"// md5.Sum(b) was removed",
	},
	"a.py": {
		"# hashlib.md5 was removed in favour of sha256",
		"NOTE = 'md5'",
		"md5sum = compute()",
		"d = hashlib.sha256(b'x')",
		`d = hashlib.new("sha256")`,
		"c = Cipher(algorithms.AES(key), modes.GCM(iv))",
		"def md5_of(path): return read(path)",
	},
	"a.js": {
		"// createHash('md5') is no longer used",
		"const algo = 'md5';",
		"const md5sum = fileHash(x);",
		"const h = crypto.createHash('sha256')",
		"const c = crypto.createCipheriv('aes-256-gcm', k, iv)",
		"const d = CryptoJS.SHA256(x)",
	},
	"a.ts": {
		"// createHash('md5') is no longer used",
		"const md5sum: string = fileHash(x);",
		"const h = crypto.createHash('sha512')",
	},
	"A.java": {
		`// MessageDigest.getInstance("MD5") was replaced`,
		`String md5 = "md5";`,
		`MessageDigest md = MessageDigest.getInstance("SHA-256");`,
		`Cipher c = Cipher.getInstance("AES/GCM/NoPadding");`,
		`Mac mac = Mac.getInstance("HmacSHA1");`,
		"String md5sum = compute();",
		// RSA "ECB" is a JCA misnomer, not a mode; OAEP is the correct and
		// recommended RSA padding. Flagging it would be a false positive on
		// code that is doing the right thing.
		`Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");`,
		`Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");`,
	},
	"A.kt": {
		`// Cipher.getInstance("DES/ECB/PKCS5Padding") was replaced`,
		"val md5sum: String = compute()",
		`val md = MessageDigest.getInstance("SHA-256")`,
	},
	"a.php": {
		"// md5() is used for cache keys here",
		"# openssl_encrypt($x, 'des-ecb', $k) was removed",
		// Bare md5()/sha1() are deliberately not matched: they are
		// overwhelmingly cache keys, ETags and Gravatar hashes, and flagging
		// them would put a finding in nearly every PHP file in existence.
		"$cacheKey = md5($url);",
		"$etag = sha1_file($path);",
		"$h = hash('sha256', $data);",
		"$md5sum = md5($contents);",
		"$gravatar = 'https://gravatar.com/avatar/' . md5(strtolower($email));",
		"$g = openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);",
	},
	"a.rb": {
		"# Digest::MD5 was replaced by SHA256",
		"md5sum = compute",
		"a = Digest::SHA256.hexdigest(x)",
		"a = OpenSSL::Cipher.new('aes-256-gcm')",
		"a = OpenSSL::Digest.new('sha256')",
		`algo = "md5"`,
	},
	"A.cs": {
		"// MD5.Create() was removed",
		`string md5 = "md5";`,
		"var a = SHA256.Create();",
		"var a = SHA512.Create();",
		"aes.Mode = CipherMode.CBC;",
		"var md5sum = Compute();",
	},
	"a.rs": {
		"// md5::compute was replaced with sha2",
		"let md5sum = String::new();",
		"let mut h = Sha256::new();",
		`let algo = "md5";`,
		"fn md5_path(p: &str) -> String { p.to_string() }",
	},
	"a.c": {
		"// MD5(data, len, out) is no longer called",
		"static const int MD5_DIGEST_LENGTH_LOCAL = 16;",
		"static char md5sum[33];",
		"MD5_CTX ctx;",
		"SHA256_Init(&ctx);",
		"const EVP_MD *m = EVP_sha256();",
		"const EVP_CIPHER *c = EVP_aes_256_gcm();",
		"compute_md5_checksum(path);",
		// OpenSSL's own dgst output format. A space before the parenthesis
		// means prose in a string literal far more often than it means a call.
		`printf("MD5 (%s) = %s\n", name, hex);`,
		`fprintf(f, "SHA1 (%s)\n", name);`,
	},
	"a.swift": {
		"// Insecure.MD5 was replaced by SHA256",
		`let md5sum = ""`,
		"let d = SHA256.hash(data: data)",
		"let alg = kCCAlgorithmAES",
	},
	"a.sh": {
		"# openssl enc -des-ecb was removed",
		// md5sum/sha1sum/shasum in shell are checksums against accidental
		// corruption, not security controls. Flagging them would bury every
		// release script in findings.
		"md5sum dist/app.tar.gz > dist/app.tar.gz.md5",
		"sha1sum -c checksums.txt",
		"shasum -a 1 file",
		`echo "expected md5: $md5"`,
		"openssl enc -aes-256-cbc -pbkdf2 -in a -out b",
		"openssl dgst -sha256 file",
	},
}

func TestIgnoresMentionsAndStrongPrimitives(t *testing.T) {
	for name, srcs := range negatives {
		for _, src := range srcs {
			if n := scanSource(t, name, src); n != 0 {
				t.Errorf("%s: got %d findings, want 0 for %q", name, n, src)
			}
		}
	}
}

// languageFamilies groups extensions that legitimately share a pattern because
// they share syntax and APIs. Anything outside a line's own family must not
// match it: a keyword that means "broken cipher" in one language is ordinary
// text in another, and letting a pattern leak across file types is how a rule
// starts inventing findings.
var languageFamilies = [][]string{
	{".go"},
	{".py"},
	{".js", ".ts"},
	{".java", ".kt"},
	{".php"},
	{".rb"},
	{".cs"},
	{".rs"},
	// Swift bridges CommonCrypto, so `CC_MD5` and `kCCAlgorithmDES` are shared
	// vocabulary with C, C++ and Objective-C rather than a leak.
	{".c", ".cpp", ".m", ".swift"},
	{".sh"},
}

func familyOf(ext string) []string {
	for _, f := range languageFamilies {
		for _, e := range f {
			if e == ext {
				return f
			}
		}
	}
	return nil
}

func TestPatternsDoNotLeakAcrossLanguages(t *testing.T) {
	allExts := []string{".go", ".py", ".js", ".ts", ".java", ".kt", ".php", ".rb",
		".cs", ".rs", ".c", ".cpp", ".m", ".swift", ".sh"}

	for name, srcs := range positives {
		own := strings.ToLower(filepath.Ext(name))
		family := familyOf(own)
		if family == nil {
			t.Fatalf("positives key %q has no declared family", name)
		}
		for _, other := range allExts {
			inFamily := false
			for _, e := range family {
				if e == other {
					inFamily = true
				}
			}
			if inFamily {
				continue
			}
			for _, src := range srcs {
				if n := scanSource(t, "x"+other, src); n != 0 {
					t.Errorf("%s source %q matched under %s — a pattern leaked across languages",
						own, src, other)
				}
			}
		}
	}
}

// Every language core's SAST supports must have a pattern, and no entry may
// name a language core does not have.
func TestCoversEverySASTLanguage(t *testing.T) {
	// core.extensionLanguages, mirrored here: weakcrypto cannot import core
	// (core imports weakcrypto), so this list is the contract between the two.
	want := []string{
		"c", "cpp", "csharp", "go", "java", "javascript", "kotlin", "objc",
		"php", "python", "ruby", "rust", "shell", "swift", "typescript",
	}
	have := map[string]bool{}
	for _, l := range languages {
		if l.pattern == nil {
			t.Errorf("language %q has a nil pattern", l.name)
		}
		if len(l.exts) == 0 {
			t.Errorf("language %q declares no extensions", l.name)
		}
		if len(l.comments) == 0 {
			t.Errorf("language %q declares no comment markers", l.name)
		}
		if have[l.name] {
			t.Errorf("language %q declared twice", l.name)
		}
		have[l.name] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("no CRYPTO-001 pattern for SAST language %q", w)
		}
	}
	for h := range have {
		found := false
		for _, w := range want {
			if w == h {
				found = true
			}
		}
		if !found {
			t.Errorf("language %q is not one of core's SAST languages", h)
		}
	}
}

// An extension may be bound to exactly one pattern. Two entries claiming the
// same extension would silently hand one language's files to another's regex.
func TestNoExtensionIsClaimedTwice(t *testing.T) {
	seen := map[string]string{}
	for _, l := range languages {
		for _, e := range l.exts {
			if prev, ok := seen[e]; ok {
				t.Errorf("extension %s claimed by both %q and %q", e, prev, l.name)
			}
			seen[e] = l.name
			if e != strings.ToLower(e) || !strings.HasPrefix(e, ".") {
				t.Errorf("%s: extension %q must be lowercase and start with a dot", l.name, e)
			}
		}
	}
}

// The reported algorithm drives the finding message, and the message drives the
// fingerprint. `_` is a word character, so a naive \b-delimited scrape silently
// falls back to a placeholder for most C and Objective-C matches.
func TestReportsTheAlgorithmName(t *testing.T) {
	for _, c := range []struct {
		name, src, want string
	}{
		{"a.c", "MD5_Init(&ctx);", "MD5"},
		{"a.c", "DES_set_key(&k, &s);", "DES"},
		{"a.c", "const EVP_CIPHER *c = EVP_aes_128_ecb();", "ECB"},
		{"a.m", "CC_SHA1(data, len, out);", "SHA1"},
		{"a.m", "CCCrypt(kCCEncrypt, kCCAlgorithmDES, 0, k, 8, NULL, i, n, o, n, &m);", "DES"},
		{"a.swift", "let opt = kCCOptionECBMode", "ECB"},
		{"A.cs", "var a = new TripleDESCryptoServiceProvider();", "TRIPLEDES"},
		{"A.cs", "var a = new SHA1Managed();", "SHA1"},
		{"a.py", "c = Cipher(algorithms.AES(key), modes.ECB())", "ECB"},
		{"a.go", "d := md5.Sum(b)", "MD5"},
	} {
		got := algorithmsFor(t, c.name, c.src)
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("%s %q: algorithm = %v, want [%s]", c.name, c.src, got, c.want)
		}
	}
}

// `modes` contains the substring "des". The algorithm scrape must not read it.
func TestAlgorithmScrapeDoesNotReadSubstrings(t *testing.T) {
	if got := algorithmIn("modes.ECB("); got != "ECB" {
		t.Errorf("algorithmIn(%q) = %q, want ECB", "modes.ECB(", got)
	}
	if got := algorithmIn("Digest::SHA1"); got != "SHA1" {
		t.Errorf("algorithmIn(%q) = %q, want SHA1", "Digest::SHA1", got)
	}
}

// Fixtures deliberately exercise weak primitives; flagging them trains people
// to ignore the rule.
func TestSkipsTestFiles(t *testing.T) {
	for _, name := range []string{
		"a_test.go", "test_a.py", "a.test.js", "a.spec.ts", "a.test.tsx",
		"a_spec.rb", "a_test.rb", "CryptoTest.java", "CryptoTests.cs",
		"CryptoTest.kt", "a_test.rs",
	} {
		src := "md5.New(); md5.Sum(b); hashlib.md5(b''); crypto.createHash('md5'); Digest::MD5; MD5_Init(&c); MD5.Create();"
		if n := scanSource(t, name, src); n != 0 {
			t.Errorf("%s: got %d findings, want 0 (test file)", name, n)
		}
	}
	for _, p := range []string{
		"src/test/java/com/x/Crypto.java",
		"pkg/testdata/sample.go",
		"web/__tests__/hash.js",
	} {
		if !source.IsTestPath(p) {
			t.Errorf("source.IsTestPath(%q) = false, want true", p)
		}
	}
	// A bare `test/` directory is a real source tree in plenty of projects and
	// must NOT be treated as fixtures — skipping it would drop findings.
	for _, p := range []string{"internal/test/helper.go", "lib/tests.go"} {
		if source.IsTestPath(p) {
			t.Errorf("source.IsTestPath(%q) = true, want false — that silently drops findings", p)
		}
	}
}

func TestUnknownExtensionIsSkipped(t *testing.T) {
	for _, name := range []string{"notes.md", "config.yaml", "data.json", "x.txt"} {
		if n := scanSource(t, name, "hashlib.md5(b'x')\nmd5.Sum(b)\nMD5_Init(&c);"); n != 0 {
			t.Errorf("%s: got %d findings, want 0", name, n)
		}
	}
}

func TestRuleIsRegistered(t *testing.T) {
	rs := (&Analyzer{}).Rules().Rules()
	// Two rules: broken primitives (this file) and insecure randomness
	// (rand.go). A rule added without a catalogue entry is invisible to
	// `nox rules`, so the count is asserted rather than only the lookup.
	if len(rs) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rs))
	}
	r, ok := (&Analyzer{}).Rules().ByID(ruleID)
	if !ok {
		t.Fatalf("%s missing from the catalogue", ruleID)
	}
	if r.Metadata["cwe"] != "CWE-327" {
		t.Errorf("cwe = %q, want CWE-327", r.Metadata["cwe"])
	}
}
