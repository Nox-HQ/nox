package lexctx

import "testing"

// TestScanObjC exercises the headline Objective-C lexical roles the same way
// TestScanGo / TestScanCPP do: one fixture, one needle per role. It pins the
// code/string/comment classification the taint and secrets analyzers rely on
// when gating findings in Objective-C source — including the ObjC-specific
// `@"..."` NSString literal, a bracket message-send line (all code), a
// preprocessor `#import`, and a data-blob NSString.
func TestScanObjC(t *testing.T) {
	src := "NSString *key = @\"s3cr3t\";\n" +
		"// line comment s3cr3t\n" +
		"/* block s3cr3t comment */\n" +
		"char c = 's';\n" +
		"const char *p = \"plain s3cr3t\";\n"
	if k := kindOfSubstring(t, LangObjC, src, `key`); k != KindCode {
		t.Errorf("identifier `key` should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangObjC, src, `@"s3cr3t"`); k != KindString {
		t.Errorf("@\"...\" NSString literal should be string (including the @), got %v", k)
	}
	if k := kindOfSubstring(t, LangObjC, src, `line comment s3cr3t`); k != KindComment {
		t.Errorf("line comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangObjC, src, `block s3cr3t comment`); k != KindComment {
		t.Errorf("block comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangObjC, src, `'s'`); k != KindString {
		t.Errorf("char literal should be string-kind, got %v", k)
	}
	if k := kindOfSubstring(t, LangObjC, src, `plain s3cr3t`); k != KindString {
		t.Errorf("plain C string literal should be string, got %v", k)
	}
}

func TestObjCLangFromPath(t *testing.T) {
	if got := LangFromPath("app/Controller.m"); got != LangObjC {
		t.Errorf("LangFromPath(.m) = %v, want %v", got, LangObjC)
	}
	if got := LangFromPath("app/Bridge.mm"); got != LangObjC {
		t.Errorf("LangFromPath(.mm) = %v, want %v", got, LangObjC)
	}
	if got := LangFromPath("APP/UPPER.M"); got != LangObjC {
		t.Errorf("LangFromPath is not case-insensitive for .m, got %v", got)
	}
	// A `.h` header must NOT be reclassified as Objective-C — it stays C/C++ so
	// the incumbent lexer keeps owning every C and C++ header.
	if got := LangFromPath("app/Header.h"); got != LangCPP {
		t.Errorf("LangFromPath(.h) = %v, want LangCPP (headers stay C/C++, not clobbered)", got)
	}
}

func TestObjCLangString(t *testing.T) {
	if got := LangObjC.String(); got != "objc" {
		t.Errorf("LangObjC.String() = %q, want %q", got, "objc")
	}
}

// TestObjCMessageSendIsCode: a bracket message send `[obj method:arg]` is all
// code — the selector and receiver are real identifiers, only the `@"..."`
// argument is a string. This pins that the recognizer sees the message-send
// bytes as code so a call/selector can be extracted downstream.
func TestObjCMessageSendIsCode(t *testing.T) {
	src := "[db executeQuery:@\"SELECT 1\" withArg:userId];\n"
	if k := kindOfSubstring(t, LangObjC, src, `executeQuery`); k != KindCode {
		t.Errorf("selector `executeQuery` should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangObjC, src, `userId`); k != KindCode {
		t.Errorf("message-send arg `userId` should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangObjC, src, `SELECT 1`); k != KindString {
		t.Errorf("@\"SELECT 1\" NSString arg should be string, got %v", k)
	}
}

// TestObjCPreprocessorImport: `#import <Foundation/Foundation.h>` — the angle
// header name is treated as a string so its `/` and `.` never begin a comment,
// and the code after the directive stays code.
func TestObjCPreprocessorImport(t *testing.T) {
	src := "#import <Foundation/Foundation.h>\nint SECRET = 1;\n"
	if k := kindOfSubstring(t, LangObjC, src, `Foundation/Foundation.h`); k != KindString {
		t.Errorf("angle header name should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangObjC, src, `SECRET`); k != KindCode {
		t.Errorf("code after an #import should be code, got %v", k)
	}
}

// TestObjCDoubleSlashInsideNSStringIsNotComment: a URL's `//` inside an
// `@"..."` NSString must not begin a comment, and trailing code stays code.
func TestObjCDoubleSlashInsideNSStringIsNotComment(t *testing.T) {
	src := "NSURL *u = [NSURL URLWithString:@\"https://example.com/x\"]; int SECRET = 1;\n"
	if k := kindOfSubstring(t, LangObjC, src, `//example`); k != KindString {
		t.Errorf("`//` inside an @\"...\" NSString must stay string, got %v", k)
	}
	if k := kindOfSubstring(t, LangObjC, src, `SECRET`); k != KindCode {
		t.Errorf("code after the NSString URL should be code, got %v", k)
	}
}

// TestObjCDataBlobInNSStringSuppressed proves the payoff: a long base64/data-URI
// payload inside an @"..." NSString is a blob (suppressed), while a short secret
// in an ordinary NSString is NOT (kept).
func TestObjCDataBlobInNSStringSuppressed(t *testing.T) {
	longBlob := "NSString *icon = @\"data:image/svg+xml;base64," +
		"AKIA1234567890ABCDEF1234567890ABAKIA1234567890ABCDEF1234567890AB==\";"
	j := indexOf(longBlob, "AKIA1234567890ABCDEF1234567890AB")
	if !InDataBlob(LangObjC, []byte(longBlob), j, j+32) {
		t.Error("a token inside a long data-URI NSString blob must be reported as a data blob")
	}

	shortSecret := []byte("NSString *apiKey = @\"AKIA1234567890ABCDEF1234567890AB\";")
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if InDataBlob(LangObjC, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in an ordinary NSString must NOT be a data blob")
	}
}

// TestObjCSuppressNonCodePolicy mirrors the C/C++ policy test for ObjC: a
// comment match is dropped by SuppressNonCode, while a short ordinary-string
// secret is kept.
func TestObjCSuppressNonCodePolicy(t *testing.T) {
	comment := []byte("int x = 1; // AKIA1234567890ABCDEF1234567890AB legacy")
	k := indexOf(string(comment), "AKIA1234567890ABCDEF1234567890AB")
	if !SuppressNonCode(LangObjC, comment, k, k+32) {
		t.Error("a token inside an ObjC comment must be suppressed by SuppressNonCode")
	}

	shortSecret := []byte("NSString *key = @\"AKIA1234567890ABCDEF1234567890AB\";")
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if SuppressNonCode(LangObjC, shortSecret, i, i+32) {
		t.Error("a short hardcoded secret in an ObjC string literal must NOT be suppressed")
	}
}

// TestObjCBoxedLiteralIsCode: `@[...]`, `@{...}`, `@(expr)` are collection/boxed
// literals whose bodies are real CODE (not strings), so a variable inside them is
// still classified as code — only `@"..."` is a string literal.
func TestObjCBoxedLiteralIsCode(t *testing.T) {
	src := "NSArray *a = @[userId, other];\n"
	if k := kindOfSubstring(t, LangObjC, src, `userId`); k != KindCode {
		t.Errorf("a variable inside an @[...] array literal should be code, got %v", k)
	}
}

// TestObjCRegionsCover guards the gap-free/contiguous contract on a mixed
// fixture (comment, NSString, char, message send).
func TestObjCRegionsCover(t *testing.T) {
	src := "// c\nNSString *s = @\"x\";\n[o m:s];\nchar q = 'z';\n"
	regions := Classify(LangObjC, []byte(src))
	regionsCover(t, regions, len(src))
}
