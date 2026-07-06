// Clean: a base64 data-URI image embedded in a Kotlin triple-quoted raw string.
// A broad secret/pattern regex trips on the long base64 run and on the `//` inside
// the URI, but lexctx classifies the whole """...""" literal as a data-blob string,
// so no code-pattern or secret finding should survive. There is no taint source and
// no sink here; any finding is a false positive.
package com.example

object Assets {
    // A raw string spanning lines with a `//` and quotes inside — none of it is code.
    val LOGO_SVG: String = """
        data:image/svg+xml;base64,
        PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIx
        MjgiIGhlaWdodD0iMTI4Ij48cmVjdCB3aWR0aD0iMTI4IiBoZWlnaHQ9IjEyOCIg
        ZmlsbD0iIzAwN2FjYyIvPjwvc3ZnPg==AKIA1234567890ABCDEFNOTAREALKEY00
    """.trimIndent()

    // A block comment containing a base64-looking blob must stay comment, not code.
    /* embedded-thumbnail: iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ== */
}
