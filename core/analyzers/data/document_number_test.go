package data

import (
	"math/rand"
	"strings"
	"testing"
)

// DATA-010..012 matched `[A-Z0-9-]{6,}` case-insensitively after the key, so
// any six-letter word was a document number. `const passport =
// require('passport')` -- the first line of every passport.js application --
// was a HIGH passport-number finding, with `require` as the number.

// documentNumbers generates values in documented formats from a seeded RNG,
// so the true positives are not hand-typed to fit the pattern.
type documentNumbers struct{ rng *rand.Rand }

func (g documentNumbers) pick(set string, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(set[g.rng.Intn(len(set))])
	}
	return b.String()
}

const decimalDigits = "0123456789"

// german: 9 characters, the first from germanPassportLead, the rest digits or
// germanPassportLetters (Passverordnung; specimen C01X00T47).
func (g documentNumbers) german() string {
	return g.pick(germanPassportLead, 1) + g.pick(decimalDigits+germanPassportLetters, 8)
}

// us: 9 digits, or a letter and 8 digits for the Next Generation Passport.
func (g documentNumbers) us(nextGen bool) string {
	if nextGen {
		return g.pick("ABCDEFGHJKLMNPRSTUVWXYZ", 1) + g.pick(decimalDigits, 8)
	}
	return g.pick(decimalDigits, 9)
}

func TestDocumentNumberRulesIgnoreCodeAndPlaceholders(t *testing.T) {
	a := NewAnalyzer()
	for _, c := range []struct{ rule, line string }{
		{"DATA-012", `const passport = require('passport');`},
		{"DATA-012", `var passport = require('passport-strategy')`},
		{"DATA-012", `import passport from 'passport';`},
		{"DATA-012", `router.post('/login', passport.authenticate('jwt'));`},
		{"DATA-012", `module.exports = { passport: passport, strategy: LocalStrategy };`},
		{"DATA-012", `export class JwtStrategy extends PassportStrategy(Strategy) {}`},
		{"DATA-012", `passport: Passportjs`},
		{"DATA-012", `passport: authentication middleware for Node.js`},
		{"DATA-012", `passport_number = models.CharField(max_length=12)`},
		{"DATA-012", `passport_no = request.form['passport_no']`},
		{"DATA-012", `passportNumber = getattr(user, 'passport_number')`},
		{"DATA-012", `passport = LOREMIPSUM`},
		{"DATA-012", `passport_number = PLACEHOLDER`},
		{"DATA-012", `passport_number = PASSPORT_NUMBER_FIELD`},
		{"DATA-012", `passport_number = sha256(raw)`},
		{"DATA-012", `passport_number: "C01X00T47abc"`},
		{"DATA-010", `patient_id = request.args.get('patient_id')`},
		{"DATA-010", `medical_record = Record.objects.get(pk=pk)`},
		{"DATA-010", `health_id = generate()`},
		{"DATA-011", `license_number = license.number`},
		{"DATA-011", `driver_license = DriverLicense(form)`},
	} {
		if scanFires(t, a, c.rule, c.line+"\n") {
			t.Errorf("%s reported code or a placeholder as a document number: %s", c.rule, c.line)
		}
	}
}

func TestDocumentNumberRulesFindRealFormats(t *testing.T) {
	g := documentNumbers{rand.New(rand.NewSource(20261024))}
	a := NewAnalyzer()
	cases := []struct{ rule, line string }{
		{"DATA-012", `passport_number: "C01X00T47"`},
		{"DATA-012", `{"passport": {"number": "GB` + g.pick(decimalDigits, 7) + `"}}`},
		{"DATA-012", `{"passport_number": "` + g.us(false) + `"}`},
		{"DATA-012", `const userPassportNumber = "` + g.us(true) + `";`},
		{"DATA-012", `passport_no = '` + g.us(false) + `'`},
		{"DATA-012", `passportNo := "` + g.us(true) + `"`},
		{"DATA-012", `:passport_number => "` + g.us(false) + `"`},
		{"DATA-012", `passport number: ` + g.german()},
		{"DATA-010", `patient_id = '` + g.pick(decimalDigits, 8) + `'`},
		{"DATA-010", `mrn = "MRN-` + g.pick(decimalDigits, 7) + `"`},
		{"DATA-011", `driver_license = 'A` + g.pick(decimalDigits, 7) + `'`},
		{"DATA-011", `"license_number": "` + g.pick(decimalDigits, 9) + `"`},
	}
	for i := 0; i < 20; i++ {
		cases = append(cases,
			struct{ rule, line string }{"DATA-012", `passport_number: "` + g.german() + `"`},
			struct{ rule, line string }{"DATA-012", `passportNo = "` + g.us(i%2 == 0) + `"`})
	}
	for _, c := range cases {
		if !scanFires(t, a, c.rule, c.line+"\n") {
			t.Errorf("%s missed a document number in a documented format: %s", c.rule, c.line)
		}
	}
}

// A German serial with no digit is real (about one in forty) and is accepted
// by its exact shape; a nine-letter word with a vowel is not.
func TestPassportValueWithoutDigits(t *testing.T) {
	for _, v := range []string{"KXTJRXHMP", "CWRMFCLRL"} {
		if !isPassportNumberMatch("passport: " + v) {
			t.Errorf("rejected a German serial with no digit: %s", v)
		}
	}
	// Vowels; a letter that cannot lead; eight and ten characters.
	for _, v := range []string{"PLACEHOLD", "XKTJRXHMP", "KXTJRXHM", "KXTJRXHMPC"} {
		if isPassportNumberMatch("passport: " + v) {
			t.Errorf("accepted an all-letters value that is not a German serial: %s", v)
		}
	}
}
