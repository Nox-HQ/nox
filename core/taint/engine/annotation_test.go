package engine

import "testing"

func TestStripLocalAnnotation(t *testing.T) {
	cases := []struct {
		in, want string
		kw       map[string]bool
	}{
		{"uid: str", "uid", pythonAnnotationKeywords},
		{"uid: Optional[str]", "uid", pythonAnnotationKeywords},
		{"self.user: User", "self.user", pythonAnnotationKeywords},
		{"id: Record<string, string>", "id", jsAnnotationKeywords},
		{"id: string | undefined", "id", jsAnnotationKeywords},
		// Colons inside brackets are not annotations.
		{`d["a:b"]`, `d["a:b"]`, pythonAnnotationKeywords},
		{"a[1:2]", "a[1:2]", pythonAnnotationKeywords},
		{"{ a: b }", "{ a: b }", jsAnnotationKeywords},
		// A clause keyword before the colon binds nothing named after it.
		{"else: x", "else: x", pythonAnnotationKeywords},
		{"default: x", "default: x", jsAnnotationKeywords},
		{"if ok: x", "if ok: x", pythonAnnotationKeywords},
		{"case 'k': x", "case 'k': x", jsAnnotationKeywords},
		{"plain", "plain", pythonAnnotationKeywords},
	}
	for _, c := range cases {
		if got := stripLocalAnnotation(c.in, c.kw); got != c.want {
			t.Errorf("stripLocalAnnotation(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
