package lexctx

import (
	"bytes"
	"testing"
)

// BenchmarkClassify substantiates the ADR's "single cheap linear pass" claim on
// a realistic mixed file (code, a big base64 blob, comments, interpolation).
func BenchmarkClassify(b *testing.B) {
	blob := bytes.Repeat([]byte("QUJDREVGR0hJSg"), 400) // ~5.6 KB base64 blob
	var buf bytes.Buffer
	buf.WriteString("const awsKey = \"AKIAIOSFODNN7EXAMPLE\";\n")
	buf.WriteString("const icon = \"data:image/png;base64,")
	buf.Write(blob)
	buf.WriteString("\";\n")
	buf.WriteString("// a comment line with AKIAIOSFODNN7EXAMPLE inside it\n")
	buf.WriteString("const u = `Bearer ${token} suffix`;\n")
	content := buf.Bytes()

	b.SetBytes(int64(len(content)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Classify(LangJavaScript, content)
	}
}
