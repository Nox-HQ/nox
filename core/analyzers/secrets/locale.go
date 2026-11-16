package secrets

import (
	"path"
	"regexp"
	"strings"
)

// A translation catalogue maps message keys to the text a user reads. The key
// `password` in one is the identifier of a form label, and its value is that
// label in some language: `password: 'Passwort'`, `confirmPassword: 'Confirm
// new password'`. SEC-080 reads exactly that shape as a hardcoded password,
// because its whole evidence is a key named like a password and a quoted
// string of eight or more characters.
//
// Measured on RAGFlow at f9a53a3: 146 of SEC-080's 198 findings were in
// web/src/locales/*.ts, one per language per password label, and none was a
// credential.
//
// The gate applies to keyNamedRules only. A rule that encodes a credential's
// format has established what it found, and is left to fire in a catalogue.
//
// The gap this leaves, stated rather than discovered later: a real password
// with no recognised format, hardcoded into a translation catalogue under a
// password-named key, is reported by nothing.

// keyNamedRules are the rules whose only evidence is the NAME of the key a
// string is assigned to.
var keyNamedRules = map[string]bool{"SEC-080": true}

// localeDirs are directory names that hold translation catalogues.
var localeDirs = map[string]bool{
	"locales": true, "locale": true, "i18n": true, "l10n": true,
	"lang": true, "langs": true, "languages": true, "translations": true,
}

// localeExts are the extensions translation catalogues are written in.
var localeExts = map[string]bool{
	".ts": true, ".js": true, ".mjs": true, ".cjs": true, ".json": true,
	".yaml": true, ".yml": true, ".po": true, ".properties": true, ".toml": true,
}

// languageTag matches a BCP 47-style tag as catalogues name their files or
// folders: en, de, pt-br, pt_BR, zh-Hant, zh-traditional, en-US.
var languageTag = regexp.MustCompile(`^(?i)[a-z]{2,3}(?:[-_][a-z0-9]{2,12})*$`)

// isLocaleCatalogue reports whether p is a translation catalogue: a file in a
// locale directory whose own name, or whose parent directory's name, is a
// language tag (locales/de.ts, i18n/en/common.json).
//
// Both halves are required. A locale directory also holds loaders and indexes
// (locales/index.ts, i18n/config.ts), and those are code, where a
// password-named assignment means what it says.
func isLocaleCatalogue(p string) bool {
	p = strings.ReplaceAll(p, `\`, "/")
	ext := path.Ext(p)
	if !localeExts[strings.ToLower(ext)] {
		return false
	}
	segs := strings.Split(path.Dir(p), "/")
	stem := strings.TrimSuffix(path.Base(p), ext)
	for i, s := range segs {
		if !localeDirs[strings.ToLower(s)] {
			continue
		}
		rest := segs[i+1:]
		switch {
		case len(rest) == 0 && languageTag.MatchString(stem):
			return true // locales/de.ts
		case len(rest) == 1 && languageTag.MatchString(rest[0]):
			return true // locales/de/common.json
		}
	}
	return false
}
