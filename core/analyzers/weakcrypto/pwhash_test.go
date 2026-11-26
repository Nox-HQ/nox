package weakcrypto

import (
	"slices"
	"testing"
)

func pwHashLines(path, src string) []int {
	var got []int
	for _, f := range scanPasswordHash(path, []byte(src)) {
		got = append(got, f.Location.StartLine)
	}
	return got
}

// A password stored as a fast digest, or derived with too little work, is
// recovered by an offline guessing attack once the hashes leak.
func TestPasswordHashWeak(t *testing.T) {
	for _, c := range []struct {
		name, path, src string
		want            []int
	}{
		// Fast digests of a password.
		{"spring md5DigestAsHex", "UserService.java", "return DigestUtils.md5DigestAsHex(password.getBytes());\n", []int{1}},
		{"commons sha256Hex", "UserService.java", "String h = DigestUtils.sha256Hex(rawPassword);\n", []int{1}},
		{"setter names the hash", "AuthService.java", "user.setPasswordHash(org.springframework.util.DigestUtils.md5DigestAsHex(\n        value.getBytes(StandardCharsets.UTF_8)));\n", []int{1}},
		{"MessageDigest one shot", "Auth.java", "byte[] d = MessageDigest.getInstance(\"MD5\").digest(phrase.getBytes(UTF_8));\n", []int{1}},
		{"MessageDigest object", "Auth.java", "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");\nbyte[] d = md.digest(passphrase.getBytes(UTF_8));\n", []int{2}},
		{"guava", "Auth.java", "String h = Hashing.sha256().hashString(password, UTF_8).toString();\n", []int{1}},
		{"python hashlib", "user.py", "return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()\n", []int{1}},
		{"python hashlib qualified", "app.py", "hash_pass = hashlib.md5(password).hexdigest()\n", []int{1}},
		{"python attribute", "main.py", "user.password = hashlib.sha256(user.password.encode()).hexdigest()\n", []int{1}},
		{"node createHash", "partners.ts", "const passwordHash = crypto.createHash('sha256').update(password).digest('hex');\n", []int{1}},
		{"node createHash target names it", "users.ts", "const passwordHash = crypto.createHash(\"md5\").update(onboardingCode).digest(\"hex\");\n", []int{1}},
		{"node body field", "api.ts", "passwordHash: crypto.createHash(\"sha256\").update(body.password).digest(\"hex\"),\n", []int{1}},
		{"cryptojs", "auth.js", "const h = CryptoJS.SHA256(password).toString();\n", []int{1}},
		{"bare helper", "route.ts", "const hashedPassword = hashMD5(password);\n", []int{1}},
		{"bare pass", "AuthController.java", "String digest = DigestUtils.md5DigestAsHex(pass.getBytes(UTF_8));\n", []int{1}},
		{"pin", "Admin.java", "u.setCallbackPinHash(DigestUtils.md5DigestAsHex(pin.getBytes()));\n", []int{1}},
		// Too little work.
		{"pbkdf2 low iterations", "Codec.java", "PBEKeySpec spec = new PBEKeySpec(phrase.toCharArray(), SALT, 1024, 128);\n", []int{1}},
		{"pbkdf2 iterations next line", "Codec.java", "PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(raw.toCharArray(), salt,\n        LEGACY_ITERATIONS, 128);\nstatic final int LEGACY_ITERATIONS = 1000;\n", []int{1}},
		{"python pbkdf2 low", "kdf.py", "dk = hashlib.pbkdf2_hmac('sha256', password, salt, 1000)\n", []int{1}},
		{"node pbkdf2 low", "kdf.js", "const key = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512');\n", []int{1}},
		{"bcrypt low fallback", "app.ts", "const passwordHash = await bcrypt.hash(password, costFactor || 4);\n", []int{1}},
		{"bcrypt low literal", "app.ts", "const h = bcrypt.hashSync(password, 4);\n", []int{1}},
		{"bcrypt genSalt low", "t.ts", "const salt = await bcrypt.genSalt(strengthLevel || 4);\n", []int{1}},
		{"python bcrypt rounds", "auth.py", "salt = bcrypt.gensalt(rounds=4)\n", []int{1}},
		// Not reported.
		{"bcrypt default", "app.ts", "const h = await bcrypt.hash(password, 12);\n", nil},
		{"bcrypt env cost", "app.ts", "const h = await bcrypt.hash(password, rounds);\n", nil},
		{"pbkdf2 enough", "Codec.java", "PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 310000, 256);\n", nil},
		{"pbkdf2 constant enough", "Codec.java", "PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, 256);\nprivate static final int ITERATIONS = 600_000;\n", nil},
		{"token digest", "tokens.ts", "const tokenHash = crypto.createHash('sha256').update(token).digest('hex');\n", nil},
		{"reset token digest", "reset.py", "digest = hashlib.sha256(password_reset_token.encode()).hexdigest()\n", nil},
		{"file checksum", "files.py", "h = hashlib.md5(chunk).hexdigest()\n", nil},
		{"password on the next statement", "files.py", "h = hashlib.md5(chunk).hexdigest()\npassword = form['password']\n", nil},
		{"pwned passwords range", "hibp.py", "# haveibeenpwned range API\nprefix = hashlib.sha1(password.encode()).hexdigest().upper()[:5]\n", nil},
		{"comment", "a.py", "# hashlib.md5(password)\n", nil},
		{"helper definition", "util.js", "function md5(password) {\n", nil},
		{"strong kdf", "a.py", "h = hashlib.scrypt(password.encode(), salt=s, n=2**14, r=8, p=1)\n", nil},
		{"passThrough is not a password", "a.js", "const h = createHash('sha256').update(passThrough).digest('hex');\n", nil},
		{"call written in a string", "seed.ts", "const hint = \"The token is MD5(email + password)\";\n", nil},
		{"result named as a pin, input is not", "auth.ts", "const expectedPin = createHash('sha256').update(user.id).digest('hex').slice(0, 4);\n", nil},
		{"http digest HA1", "auth.js", "var ha1 = md5(user + ':' + challenge.realm + ':' + pass);\n", nil},
		{"mongodb-cr", "mongocr.js", "const md5 = crypto.createHash('md5');\nmd5.update(`${username}:mongo:${password}`, 'utf8');\n", nil},
		{"challenge response", "login.js", "const proof = sha256(nonce + hashedPassword);\n", nil},
	} {
		if got := pwHashLines(c.path, c.src); !slices.Equal(got, c.want) {
			t.Errorf("%s: lines %v, want %v", c.name, got, c.want)
		}
	}
}
