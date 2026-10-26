package depimports

import "testing"

func jsUse(t *testing.T, file, src, spec, name string) bool {
	t.Helper()
	ix := New()
	ix.Add(file, []byte(src))
	_, ok := ix.JSSymbolUse(spec, name)
	return ok
}

// Every ordinary way of importing and using an export must be seen. The taint
// work found that only the one unusual spelling used to work.
func TestJSSymbolUseOrdinaryIdioms(t *testing.T) {
	cases := []struct{ name, file, src, spec, sym string }{
		{"esm named", "a.js", "import { sendMail } from 'nodemailer';\nsendMail(1);", "nodemailer", "sendMail"},
		{"esm named alias", "a.js", "import { sendMail as send } from 'nodemailer';\nsend(1);", "nodemailer", "sendMail"},
		{"esm default member", "a.js", "import nm from 'nodemailer';\nnm.createTransport();", "nodemailer", "createTransport"},
		{"esm default called", "a.js", "import multer from 'multer';\nconst up = multer({});", "multer", "default"},
		{"esm namespace member", "a.ts", "import * as nm from 'nodemailer';\nnm.createTransport();", "nodemailer", "createTransport"},
		{"esm default plus named", "a.js", "import nm, { createTransport } from 'nodemailer';\ncreateTransport();", "nodemailer", "createTransport"},
		{"esm default plus namespace", "a.js", "import nm, * as all from 'nodemailer';\nall.createTransport();", "nodemailer", "createTransport"},
		{"esm multiline", "a.ts", "import {\n  a,\n  sendMail,\n} from 'nodemailer';\nsendMail();", "nodemailer", "sendMail"},
		{"esm default as", "a.js", "import { default as nm } from 'nodemailer';\nnm();", "nodemailer", "default"},
		{"esm subpath", "a.js", "import { parse } from 'nodemailer/lib/addressparser';\nparse();", "nodemailer/lib/addressparser", "parse"},
		{"esm subpath with extension", "a.js", "import { parse } from 'nodemailer/lib/addressparser/index.js';\nparse();", "nodemailer/lib/addressparser", "parse"},
		{"esm scoped", "a.ts", "import { x } from '@scope/pkg';\nx();", "@scope/pkg", "x"},
		{"esm inline type skipped but value used", "a.ts", "import { type T, f } from 'm';\nf();", "m", "f"},
		{"cjs whole member", "a.js", "const nm = require('nodemailer');\nnm.createTransport();", "nodemailer", "createTransport"},
		{"cjs whole called", "a.js", "const multer = require('multer');\nmulter({});", "multer", "default"},
		{"cjs destructure", "a.js", "const { sendMail } = require('nodemailer');\nsendMail();", "nodemailer", "sendMail"},
		{"cjs destructure rename", "a.js", "const { sendMail: send, other } = require('nodemailer');\nsend();", "nodemailer", "sendMail"},
		{"cjs destructure default value", "a.js", "const { sendMail = noop } = require('nodemailer');\nsendMail();", "nodemailer", "sendMail"},
		{"cjs member bound", "a.js", "const send = require('nodemailer').sendMail;\nsend();", "nodemailer", "sendMail"},
		{"cjs inline member call", "a.js", "require('nodemailer').sendMail();", "nodemailer", "sendMail"},
		{"cjs inline default call", "a.js", "require('multer')({});", "multer", "default"},
		{"cjs call result", "a.js", "const up = require('multer')({});", "multer", "default"},
		{"cjs var and let", "a.js", "var nm = require(\"nodemailer\");\nnm.f();", "nodemailer", "f"},
		{"cjs second declarator", "a.js", "const a = require('a'), nm = require('nodemailer');\nnm.f();", "nodemailer", "f"},
		{"cjs bracket access", "a.js", "const nm = require('nodemailer');\nnm['createTransport']();", "nodemailer", "createTransport"},
		{"cjs destructure from whole", "a.js", "const nm = require('nodemailer');\nconst { createTransport } = nm;", "nodemailer", "createTransport"},
		{"dynamic import namespace", "a.js", "async function f(){ const nm = await import('nodemailer'); nm.createTransport(); }", "nodemailer", "createTransport"},
		{"dynamic import destructure", "a.js", "async function f(){ const { createTransport } = await import('nodemailer'); createTransport(); }", "nodemailer", "createTransport"},
		{"ts import equals", "a.ts", "import nm = require('nodemailer');\nnm.createTransport();", "nodemailer", "createTransport"},
		{"optional chaining", "a.js", "const nm = require('nodemailer');\nnm?.createTransport();", "nodemailer", "createTransport"},
		{"jsx file", "a.jsx", "import { f } from 'm';\nexport const A = () => <b>{f()}</b>;", "m", "f"},
		{"no semicolons", "a.js", "import { f } from 'm'\nconst x = f()\n", "m", "f"},
		{"mjs", "a.mjs", "import { f } from 'm';\nf();", "m", "f"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !jsUse(t, c.file, c.src, c.spec, c.sym) {
				t.Errorf("%s: no use of %s.%s found in %q", c.name, c.spec, c.sym, c.src)
			}
		})
	}
}

// A use that is not one must not be reported: each of these would otherwise
// raise a finding on something the project never does.
func TestJSSymbolUseNegatives(t *testing.T) {
	cases := []struct{ name, file, src, spec, sym string }{
		{"imported, never referenced", "a.js", "import { sendMail } from 'nodemailer';\n", "nodemailer", "sendMail"},
		{"required, never referenced", "a.js", "const { sendMail } = require('nodemailer');\n", "nodemailer", "sendMail"},
		{"other member", "a.js", "const nm = require('nodemailer');\nnm.createTransport();", "nodemailer", "sendMail"},
		{"same name on another object", "a.js", "import { x } from 'nodemailer';\nother.x();", "nodemailer", "x"},
		{"in a comment", "a.js", "import { x } from 'm';\n// x();\n/* x() */", "m", "x"},
		{"in a string", "a.js", "import { x } from 'm';\nconst s = 'x()';", "m", "x"},
		{"commented import", "a.js", "// import { x } from 'm';\nx();", "m", "x"},
		{"import in a string", "a.js", "const s = \"import { x } from 'm'\";\nx();", "m", "x"},
		{"type only import", "a.ts", "import type { x } from 'm';\nx();", "m", "x"},
		{"relative", "a.js", "import { x } from './m';\nx();", "./m", "x"},
		{"node builtin", "a.js", "import { x } from 'node:fs';\nx();", "node:fs", "x"},
		{"object key not a use", "a.js", "import { x } from 'm';\nconst o = { x: 1 };", "m", "x"},
		{"shadowing declaration", "a.js", "import { x } from 'm';\nfunction x() {}", "m", "x"},
		{"test file", "a.test.js", "import { x } from 'm';\nx();", "m", "x"},
		{"tests dir", "src/__tests__/a.js", "import { x } from 'm';\nx();", "m", "x"},
		{"inline type member", "a.ts", "import { type x } from 'm';\nlet y: x;", "m", "x"},
		{"then chain", "a.js", "import('m').then(m => m.x);", "m", "x"},
		{"module value only passed on", "a.js", "const nm = require('nodemailer');\nuse(nm);", "nodemailer", "default"},
		{"re-export is not a call", "a.js", "export { x } from 'm';", "m", "x"},
		{"different package", "a.js", "import { x } from 'other';\nx();", "m", "x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if jsUse(t, c.file, c.src, c.spec, c.sym) {
				t.Errorf("%s: reported a use of %s.%s in %q", c.name, c.spec, c.sym, c.src)
			}
		})
	}
}

func TestJSSymbolUseWitnessIsDeterministicAndLocated(t *testing.T) {
	a, b := New(), New()
	files := map[string]string{
		"z.js": "import { f } from 'm';\n\nf();",
		"a.js": "import { f } from 'm';\nf();",
	}
	for _, name := range []string{"z.js", "a.js"} {
		a.Add(name, []byte(files[name]))
	}
	for _, name := range []string{"a.js", "z.js"} {
		b.Add(name, []byte(files[name]))
	}
	ua, _ := a.JSSymbolUse("m", "f")
	ub, _ := b.JSSymbolUse("m", "f")
	if ua != ub || ua.File != "a.js" || ua.Line != 2 {
		t.Errorf("witness depends on order or is wrong: %v %v", ua, ub)
	}
}
