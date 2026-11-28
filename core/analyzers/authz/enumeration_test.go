package authz

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func enumLines(path string, lang lexctx.Lang, src string) []int {
	var got []int
	for _, f := range scanEnumeration(path, lang, []byte(src)) {
		got = append(got, f.Location.StartLine)
	}
	return got
}

// A login or password-reset path that answers "no such account" differently
// from a wrong password tells a caller which accounts exist.
func TestAccountEnumeration(t *testing.T) {
	J, JS, PY := lexctx.LangJava, lexctx.LangJavaScript, lexctx.LangPython
	for _, c := range []struct {
		name, path string
		lang       lexctx.Lang
		src        string
		want       []int
	}{
		{"spring login", "AuthController.java", J,
			"@PostMapping(\"/login\")\npublic ResponseEntity<?> login(@RequestBody LoginRequest r) {\n    User u = repo.findByEmail(r.email());\n    if (u == null) {\n        return ResponseEntity.status(401).body(new ErrorResponse(\"No account is registered with that e-mail\"));\n    }\n    return ok();\n}\n", []int{5}},
		{"reset request in a lambda", "UserLifecycleService.java", J,
			"public void requestPasswordReset(String email) {\n    User u = users.find(email).orElseThrow(() -> new ApiException(\"NOT_FOUND\", \"No account is registered with that address\"));\n}\n", []int{2}},
		{"chinese message in loadUserByUsername", "UserDetailsServiceImpl.java", J,
			"public UserDetails loadUserByUsername(String username) {\n    if (user == null) {\n        throw new BadRequestException(\"用户不存在\");\n    }\n}\n", []int{3}},
		{"user [x] not found", "UserFacadeImpl.java", J,
			"public void requestPasswordReset(String userName, Store store) {\n    throw new ResourceNotFoundException(\"User [\" + userName + \"] not found for store [\" + store.getCode() + \"]\");\n}\n", []int{2}},
		{"error code", "InternalAuthController.java", J,
			"@PostMapping(\"/reset/start\")\npublic ResponseEntity<?> startReset(@RequestBody Map<String, String> b) {\n    if (u == null) return ResponseEntity.status(404).body(Map.of(\"error\", \"no_marketplace_account\"));\n    return ok();\n}\n", []int{3}},
		{"express forgot-password route", "auth.js", JS,
			"router.post('/forgot-password', async (req, res) => {\n  const user = await User.findOne({ email: req.body.email });\n  if (!user) return res.status(404).json({ error: 'User not found' });\n  res.json({ ok: true });\n});\n", []int{3}},
		{"nest login", "auth.service.ts", JS,
			"export class AuthService {\n  async login(dto: LoginDto): Promise<Token> {\n    const user = await this.users.findOne(dto.email);\n    if (!user) {\n      throw new UnauthorizedException('Email not registered');\n    }\n  }\n}\n", []int{5}},
		{"flask reset", "views.py", PY,
			"@app.route('/reset', methods=['POST'])\ndef reset():\n    user = User.query.filter_by(email=email).first()\n    if not user:\n        return jsonify(error=\"No user with that email\"), 404\n    return jsonify(ok=True)\n", []int{5}},
		// Not reported.
		{"generic login failure", "AuthController.java", J,
			"public ResponseEntity<?> login(LoginRequest r) {\n    if (u == null || !enc.matches(r.password(), u.hash())) {\n        return ResponseEntity.status(401).body(new ErrorResponse(\"Invalid email or password\"));\n    }\n}\n", nil},
		{"the safe reset reply", "ForgotPasswordView.java", J,
			"public void forgotPassword(String email) {\n    Ui.success(\"If that account exists, a reset link was sent.\");\n}\n", nil},
		{"spring hides UsernameNotFoundException", "UserDetailsServiceImpl.java", J,
			"public UserDetails loadUserByUsername(String username) {\n    return repo.find(username).orElseThrow(() -> new UsernameNotFoundException(\"User not found\"));\n}\n", nil},
		{"not an authentication path", "ProfileController.java", J,
			"public Profile profile(Long id) {\n    return repo.findById(id).orElseThrow(() -> new NotFoundException(\"User not found\"));\n}\n", nil},
		{"next method after a login method", "AuthController.java", J,
			"public void login(LoginRequest r) {\n    auth(r);\n}\n\npublic Profile profile(Long id) {\n    throw new NotFoundException(\"User not found\");\n}\n", nil},
		{"a log line, not the response", "AuthService.java", J,
			"public Token login(String email) {\n    log.warn(\"login: user not found {}\", email);\n    throw new BadCredentialsException(\"Invalid credentials\");\n}\n", nil},
		{"comment", "AuthService.java", J,
			"public Token login(String email) {\n    // previously: \"User not found\"\n    throw new BadCredentialsException(\"Invalid credentials\");\n}\n", nil},
		{"registration is out of scope", "AuthService.java", J,
			"public User register(String email) {\n    throw new ValidationException(\"An account with this email already exists\");\n}\n", nil},
		{"an unknown caller is not an unknown account", "HibernateUserDAO.java", J,
			"public void changePassword(User u, String pw) {\n    throw new DAOException(\"Illegal attempt to change user password from unknown caller\");\n}\n", nil},
		{"no user context", "Context.java", J,
			"public static void authenticate(Credentials c) {\n    log(\"x\");\n    throw new IllegalStateException(\"assuming no user context has been defined\");\n}\n", nil},
		{"lookup by an id the caller already holds", "UserService.java", J,
			"public void resetPassword(ResetToken token, String pw) {\n    User user = users.findById(token.getUserId()).orElseThrow(() -> AppException.notFound(\"User not found.\"));\n}\n", nil},
		{"no user here", "app.py", PY,
			"@app.route('/forgot', methods=['POST'])\ndef forgot():\n    return jsonify({'Error': 'No User here...'}), 404\n", []int{3}},
		{"python: the def around the message, not a nested helper above it", "views.py", PY,
			"def login():\n    def helper():\n        return 1\n    return jsonify(error=\"User not found\"), 404\n", []int{4}},
		{"python: the route decorator names the path", "api.py", PY,
			"@app.post(\"/login\")\ndef handle():\n    return {\"error\": \"User not found\"}\n", []int{3}},
		{"java: the route annotation names the path", "AuthController.java", J,
			"@PostMapping(\"/forgot-password\")\npublic String submit(@RequestParam String email, Model model) {\n    model.addAttribute(\"error\", \"No account is registered for \" + email);\n    return \"forgot\";\n}\n", []int{3}},
		{"one message for both cases", "AuthController.java", J,
			"public ResponseEntity<?> login(LoginRequest r) {\n    return ResponseEntity.status(401).body(new ErrorResponse(\"Email not registered or wrong password\"));\n}\n", nil},
		{"python non-auth view", "views.py", PY,
			"def login():\n    return render()\n\ndef profile(uid):\n    return jsonify(error=\"User not found\"), 404\n", nil},
	} {
		if got := enumLines(c.path, c.lang, c.src); !slices.Equal(got, c.want) {
			t.Errorf("%s: lines %v, want %v", c.name, got, c.want)
		}
	}
}
