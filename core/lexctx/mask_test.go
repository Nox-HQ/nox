package lexctx

import "testing"

func TestMaskNonCode(t *testing.T) {
	for _, c := range []struct {
		lang      Lang
		src, want string
	}{
		{LangPython, "a = 'tok' # token = x\n", "a = '   '            \n"},
		{LangPython, "q = f\"x{b}y\"\n", "q = f\" {b} \"\n"},
		{LangPython, "d = \"\"\"doc\nmore\"\"\"\n", "d = \"\"\"   \n    \"\"\"\n"},
		{LangPython, "r = rb'q'\n", "r = rb' '\n"},
		{LangJavaScript, "x = \"s\" // c\n", "x = \" \"     \n"},
	} {
		got := string(MaskNonCode(c.lang, []byte(c.src)))
		if got != c.want {
			t.Errorf("MaskNonCode(%q)\n got %q\nwant %q", c.src, got, c.want)
		}
		if len(got) != len(c.src) {
			t.Errorf("length changed for %q", c.src)
		}
	}
}
