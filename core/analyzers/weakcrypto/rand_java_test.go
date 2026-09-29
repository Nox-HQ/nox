package weakcrypto

import "testing"

func javaClass(body string) string {
	return "package p;\nimport java.util.Random;\npublic class A {\n" + body + "\n}\n"
}

func TestJavaFlagsSecurityUseOfRandom(t *testing.T) {
	for _, c := range []struct{ name, src, wantCtx string }{
		{"security-named local", javaClass("  void f() {\n    long token = new Random().nextLong();\n    use(token);\n  }"), "token"},
		{"one forward hop through a neutral local", javaClass("  public void doPost() {\n    float rand = new java.util.Random().nextFloat();\n    String rememberMeKey = Float.toString(rand).substring(2);\n    session.setAttribute(name, rememberMeKey);\n  }"), "remember_me_key"},
		{"Math.random", javaClass("  void f() {\n    double value = java.lang.Math.random();\n    String resetToken = Double.toString(value);\n  }"), "reset_token"},
		{"a Random local", javaClass("  private final Random rng = new Random();\n  String newPassword() {\n    return Integer.toString(rng.nextInt());\n  }"), "new_password"},
		{"nextBytes names its buffer", javaClass("  void f() {\n    byte[] salt = new byte[16];\n    new Random().nextBytes(salt);\n  }"), "salt"},
		{"ThreadLocalRandom", "package p;\nimport java.util.concurrent.ThreadLocalRandom;\nclass A {\n  void f() {\n    int otp = ThreadLocalRandom.current().nextInt(100000, 999999);\n  }\n}\n", "otp"},
		{"RandomStringUtils", "package p;\nclass A {\n  void f() {\n    String apiKey = RandomStringUtils.randomAlphanumeric(32);\n  }\n}\n", "api_key"},
		{"setter named for a secret", javaClass("  void f(User u) {\n    u.setSessionId(Long.toString(new Random().nextLong()));\n  }"), "set_session_id"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := scanGo(t, "src/main/java/A.java", c.src)
			if len(got) != 1 {
				t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
			}
			if ctx := got[0].Metadata["context"]; ctx != c.wantCtx {
				t.Fatalf("blames %q, want %q", ctx, c.wantCtx)
			}
		})
	}
}

func TestJavaIgnoresBenignOrSecureRandomness(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{"SecureRandom", "package p;\nimport java.security.SecureRandom;\nclass A {\n  void f() {\n    long token = new SecureRandom().nextLong();\n  }\n}\n"},
		{"SecureRandom behind a Random type", "package p;\nimport java.util.Random;\nimport java.security.SecureRandom;\nclass A {\n  Random r = new SecureRandom();\n  void f() {\n    long token = r.nextLong();\n  }\n}\n"},
		{"SecureRandom.getInstance", "package p;\nclass A {\n  void f() throws Exception {\n    long token = java.security.SecureRandom.getInstance(\"SHA1PRNG\").nextLong();\n  }\n}\n"},
		{"neutral use", javaClass("  void f() {\n    int n = new Random().nextInt(10);\n    System.out.println(n);\n  }")},
		{"jitter vetoes", javaClass("  void refreshToken() {\n    long backoffMillis = new Random().nextInt(1000);\n    Thread.sleep(backoffMillis);\n  }")},
		{"picking an element", javaClass("  void f(java.util.List<String> keys) {\n    String key = keys.get(new Random().nextInt(keys.size()));\n  }")},
		{"comment", javaClass("  void f() {\n    // long token = new Random().nextLong();\n  }")},
		{"string", javaClass("  void f() {\n    String doc = \"long token = new Random().nextLong();\";\n  }")},
		{"another package's Random", "package p;\nimport org.example.Random;\nclass A {\n  void f() {\n    long token = new Random().nextLong();\n  }\n}\n"},
		{"a duration is not a secret (Kafka SASL)", javaClass("  void f() {\n    double pctToUse = 0.8 + RNG.nextDouble() * 0.1;\n    long sessionLifetimeMsToUse = (long) (lifetime * pctToUse);\n  }\n  static final Random RNG = new Random();")},
		{"an index is a pick (Kafka SmokeTestDriver)", javaClass("  void f() {\n    final int index = new Random().nextInt(numKeys);\n    final String key = keys[index];\n  }")},
		{"scrubbing a secret on close (Keycloak vault)", javaClass("  public void close() {\n    for (int i = 0; i < this.secretArray.length; i++) {\n      this.secretArray[i] = (char) java.util.concurrent.ThreadLocalRandom.current().nextInt();\n    }\n  }")},
		{"forward hop stops at reassignment", javaClass("  void f() {\n    long v = new Random().nextLong();\n    v = 0;\n    String sessionKey = Long.toString(v);\n  }")},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := scanGo(t, "src/main/java/A.java", c.src); len(got) != 0 {
				t.Fatalf("want no finding, got %+v", got)
			}
		})
	}
}

func TestJavaRandSkipsTestFiles(t *testing.T) {
	src := javaClass("  void f() {\n    long token = new Random().nextLong();\n  }")
	if got := scanGo(t, "src/test/java/ATest.java", src); len(got) != 0 {
		t.Fatalf("test source reported: %+v", got)
	}
}
