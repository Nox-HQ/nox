package lexctx

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// LooksLikeJWT reports whether s is structurally a JSON Web Token.
//
// It lives here, in the lowest layer, because two consumers need it and they
// must agree: the secrets analyzer records "this is a JWT" as a deterministic
// claim, and the data-blob refiner must NOT drop a real JWT as an opaque
// payload. A JWT is a credential that happens to be long, and length is exactly
// what a blob heuristic cannot tell apart from a base64 image chunk — so the
// heuristic needs a structural check to defer to, and that check has to be the
// same one the analyzer uses or the two will disagree about what a JWT is.
//
// Structural, offline, and about the token's shape rather than its validity: it
// decodes the header and confirms a signing algorithm is named, never that the
// signature holds — that needs a key nox does not have. A string matching the
// loose `eyJ....eyJ....` pattern whose header does not decode to a JSON object
// with an `alg` field is not a JWT, and saying so is the whole value.
func LooksLikeJWT(s string) bool {
	s = strings.TrimSpace(strings.Trim(s, `"'`))
	s = strings.TrimPrefix(s, "Bearer ")
	s = strings.TrimPrefix(s, "bearer ")

	parts := strings.Split(s, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var claims map[string]any
	if err := json.Unmarshal(header, &claims); err != nil {
		return false
	}
	if _, ok := claims["alg"]; !ok {
		return false
	}
	_, err = base64.RawURLEncoding.DecodeString(parts[1])
	return err == nil
}

// LooksJWTShaped reports whether s has the three-dot-segment shape of a JWT,
// regardless of whether the segments decode. It is the "is this checkable at
// all" question, distinct from LooksLikeJWT's "is it a real one".
func LooksJWTShaped(s string) bool {
	s = strings.TrimSpace(strings.Trim(s, `"'`))
	s = strings.TrimPrefix(s, "Bearer ")
	s = strings.TrimPrefix(s, "bearer ")
	parts := strings.Split(s, ".")
	return len(parts) == 3 && parts[0] != "" && parts[1] != "" && parts[2] != "" &&
		strings.HasPrefix(parts[0], "eyJ")
}
