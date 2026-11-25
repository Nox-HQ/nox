package logleak

import (
	"regexp"
	"strings"
	"unicode"
)

// credentialWords are the words of a name that holds a credential's value.
var credentialWords = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "passphrase": true,
	"secret": true, "token": true, "bearer": true, "authorization": true,
	"credential": true, "credentials": true, "otp": true, "apikey": true,
	"ssn": true, "cvv": true, "cvc": true, "iban": true, "cookie": true, "tok": true,
}

// credentialPairs are two-word credentials: api_key, private_key, card
// number, national id.
var credentialPairs = map[[2]string]bool{
	{"api", "key"}: true, {"private", "key"}: true, {"access", "key"}: true,
	{"secret", "key"}: true, {"card", "number"}: true, {"national", "identifier"}: true,
	{"national", "id"}: true, {"account", "number"}: true, {"passport", "number"}: true,
	{"auth", "header"}: true, {"session", "cookie"}: true,
}

// notTheValue are words that make a name about a credential rather than the
// credential: its type, length, validity, the service that issues it.
var notTheValue = map[string]bool{
	"is": true, "has": true, "should": true, "can": true, "need": true, "needs": true,
	"changed": true, "valid": true, "invalid": true, "expired": true, "expire": true,
	"expires": true, "expiry": true, "expiration": true, "missing": true, "required": true,
	"match": true, "matches": true, "mismatch": true, "policy": true, "strength": true,
	"min": true, "max": true, "length": true, "len": true, "count": true, "type": true,
	"ttl": true, "status": true, "name": true, "id": true, "ids": true, "hash": true,
	"hashed": true, "digest": true, "prefix": true, "suffix": true, "last": true,
	"masked": true, "mask": true, "redacted": true, "hint": true, "label": true,
	"field": true, "fields": true, "url": true, "endpoint": true, "path": true,
	"uri": true, "service": true, "svc": true, "repository": true, "repo": true,
	"manager": true, "provider": true, "util": true, "utils": true, "helper": true,
	"generator": true, "encoder": true, "validator": true, "store": true,
	"client": true, "factory": true, "config": true, "settings": true,
	"tokens": true, "tokenizer": true, "tokenize": true, "usage": true, "limit": true,
	"budget": true, "requested": true, "sent": true, "created": true, "updated": true,
	"failed": true, "success": true, "succeeded": true, "attempt": true,
	"attempts": true, "error": true, "errors": true, "verified": true,
	"enabled": true, "disabled": true, "arn": true, "ref": true, "version": true,
	"at": true, "date": true, "time": true, "age": true, "used": true, "rotation": true,
	"preview": true, "directory": true, "dir": true, "file": true, "folder": true,
	"location": true, "regex": true, "pattern": true, "format": true, "rule": true,
	"life": true, "lifetime": true, "duration": true, "timeout": true,
}

// The value of a chain whose earlier part is the credential, as in
// token.value or secret.getValue().
var valueAccessors = map[string]bool{
	"value": true, "getvalue": true, "get": true, "tostring": true, "raw": true,
	"plain": true, "plaintext": true, "string": true, "text": true, "reveal": true,
	"expose": true, "exposesecret": true, "getsecret": true, "getplaintext": true,
}

var (
	chainRe = regexp.MustCompile(`[A-Za-z_$][\w$]*(?:\s*(?:\?\.|\.)\s*[A-Za-z_$][\w$]*(?:\s*\(\s*\))?)*`)
	// Measured, tested or cut: not the value.
	measuredAfterRe = regexp.MustCompile(`^\s*(?:(?:\?\.|\.)\s*(?:length|size|isEmpty|isBlank|startsWith|endsWith|substring|slice|substr|count|hashCode)\b|[!=]==?|\?\s*[^.?]|\bis\s+(?:not\s+)?None\b|\[\s*-?\d*\s*:)`)
	negatedBeforeRe = regexp.MustCompile(`(?:!|\bnot\s+|\btypeof\s+)\s*$`)
)

var segSplitRe = regexp.MustCompile(`\?\.|\.`)

// credentialValue returns the first expression in code that is a
// credential's value, or "".
func credentialValue(code string) string {
	for _, m := range chainRe.FindAllStringIndex(code, -1) {
		chain := code[m[0]:m[1]]
		// A keyword argument's name or an object key is not a value.
		after := code[m[1]:]
		if strings.HasPrefix(strings.TrimLeft(after, " \t"), ":") && !strings.HasPrefix(strings.TrimLeft(after, " \t"), "::") {
			// `{ token: x }` keys and TypeScript annotations: the value is
			// what follows, read on its own.
			continue
		}
		if strings.HasPrefix(strings.TrimLeft(after, " \t"), "=") && !strings.HasPrefix(strings.TrimLeft(after, " \t"), "==") {
			continue // Python keyword argument name
		}
		if strings.HasPrefix(strings.TrimLeft(after, " \t"), "(") || strings.HasSuffix(chain, ")") {
			// A call: the callee's name is what it does, not what it holds,
			// unless it reads a credential (getPassword(), generateToken(u))
			// or a credential's value (cookie.getValue()).
			last := lastSegment(chain)
			if !getterOfCredential(last) && !valueAccessors[strings.ToLower(last)] && !recordAccessor(chain, last) {
				continue
			}
		}
		if !chainIsCredential(chain) {
			continue
		}
		if measuredAfterRe.MatchString(after) || negatedBeforeRe.MatchString(code[:m[0]]) || computedFrom(code, m[0]) {
			continue
		}
		return strings.Join(strings.Fields(chain), "")
	}
	return ""
}

// passThrough are calls whose result still shows their argument: string
// forming and serialising.
var passThrough = map[string]bool{
	"format": true, "valueof": true, "str": true, "repr": true, "string": true,
	"tostring": true, "stringify": true, "join": true, "dumps": true, "inspect": true,
	"concat": true, "tuple": true, "list": true, "dict": true, "of": true,
	"aslist": true, "sprintf": true, "printf": true, "ascii": true, "encode": true,
	"decode": true, "formatted": true, "append": true, "print": true,
}

var calleeRe = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*$`)

// computedFrom reports whether the expression at off sits inside the
// arguments of a call that computes something from it -- isExpired(token),
// mask(token), len(password), hash_password(password): the log then shows
// the result, not the credential.
func computedFrom(code string, off int) bool {
	depth := 0
	for i := off - 1; i >= 0; i-- {
		switch code[i] {
		case ')', ']', '}':
			depth++
		case '[', '{':
			if depth > 0 {
				depth--
			}
		case '(':
			if depth > 0 {
				depth--
				continue
			}
			m := calleeRe.FindStringSubmatch(code[:i])
			if len(m) < 2 || passThrough[strings.ToLower(m[1])] {
				continue // a bare group or tuple, or a pass-through call
			}
			switch m[1] {
			case "if", "for", "while", "in", "and", "or", "not", "return", "else":
				continue
			}
			return true
		}
	}
	return false
}

func lastSegment(chain string) string {
	segs := segments(chain)
	return segs[len(segs)-1]
}

func segments(chain string) []string {
	var out []string
	for _, s := range segSplitRe.Split(chain, -1) {
		s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "()"))
		s = strings.TrimSpace(strings.TrimSuffix(s, "("))
		if s != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	if len(out) == 0 {
		out = []string{chain}
	}
	return out
}

// getterOfCredential: getPassword, getToken, generateToken, createSecret.
func getterOfCredential(name string) bool {
	w := words(name)
	if len(w) < 2 {
		return false
	}
	switch w[0] {
	case "get", "fetch", "load", "read", "find", "generate", "create", "issue", "make", "new", "sign", "reveal", "decrypt":
		return nameIsCredential(name)
	}
	return false
}

// actionWords start a method name that does something to a credential
// rather than return it.
var actionWords = map[string]bool{
	"verify": true, "validate": true, "check": true, "refresh": true, "rotate": true,
	"revoke": true, "invalidate": true, "clear": true, "reset": true, "remove": true,
	"delete": true, "store": true, "save": true, "set": true, "update": true,
	"parse": true, "decode": true, "encode": true, "hash": true, "mask": true,
	"compare": true, "send": true, "handle": true, "process": true, "require": true,
	"ensure": true, "assert": true, "extract": true, "build": true, "apply": true,
}

// recordAccessor: a zero-argument call named for the credential itself --
// a Java record's request.accountNumber(), a Python property-like
// user.password() -- returns the value.
func recordAccessor(chain, last string) bool {
	if !strings.HasSuffix(chain, ")") {
		return false
	}
	w := words(last)
	return len(w) > 0 && !actionWords[w[0]] && nameIsCredential(last)
}

// chainIsCredential: the last segment names a credential, or an earlier one
// does and the last reads its value.
func chainIsCredential(chain string) bool {
	segs := segments(chain)
	last := segs[len(segs)-1]
	if nameIsCredential(last) {
		return true
	}
	if !valueAccessors[strings.ToLower(last)] {
		return false
	}
	for _, s := range segs[:len(segs)-1] {
		if nameIsCredential(s) {
			return true
		}
	}
	return false
}

// formWords end the name of a submitted form or its object.
var formWords = map[string]bool{
	"dto": true, "request": true, "req": true, "form": true, "input": true,
	"payload": true, "body": true, "data": true, "params": true, "command": true,
}

// signInForm reports a sign-in, sign-up or registration form object
// (loginDto, signupRequest, registerForm): it carries the password.
func signInForm(w []string) bool {
	if len(w) < 2 || !formWords[w[len(w)-1]] {
		return false
	}
	for i, x := range w {
		switch x {
		case "login", "signin", "signup", "register", "registration":
			return true
		case "in", "up":
			if i > 0 && w[i-1] == "sign" {
				return true
			}
		}
	}
	return false
}

// nameIsCredential reports whether an identifier names a credential's value.
func nameIsCredential(name string) bool {
	w := words(name)
	if signInForm(w) {
		return true
	}
	found := false
	for i, x := range w {
		if notTheValue[x] {
			return false
		}
		if credentialWords[x] {
			found = true
		}
		if i > 0 && credentialPairs[[2]string{w[i-1], x}] {
			found = true
		}
	}
	return found
}

// words splits camelCase, PascalCase, snake_case and SCREAMING_CASE into
// lower-case words; "API_KEY" and "apiKey" both give [api key].
func words(name string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(strings.TrimPrefix(name, "$"))
	for i, r := range rs {
		switch {
		case r == '_' || r == '$' || r == '-':
			flush()
		case unicode.IsUpper(r):
			// Start a word at a lower->Upper change, or at the last capital
			// of an acronym followed by lower case (JWTToken -> jwt token).
			if i > 0 && (unicode.IsLower(rs[i-1]) || unicode.IsDigit(rs[i-1]) ||
				(i+1 < len(rs) && unicode.IsLower(rs[i+1]) && unicode.IsUpper(rs[i-1]))) {
				flush()
			}
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return out
}
