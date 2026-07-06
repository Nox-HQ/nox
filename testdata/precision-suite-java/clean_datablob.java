// Data-blob stressor: a long base64 data-URI embedded as a Java text block, plus
// public digests (a git SHA and an SRI-style integrity hash) that merely LOOK
// high-entropy. None is a secret — the lexctx text-block blob gating and the
// digest suppressions keep this clean. Zero findings expected.
package com.example.assets;

public final class Assets {

    // A base64-encoded 1x1 transparent PNG as a data URI — image data, not a
    // credential. Rendered as a Java text block so it spans lines like real
    // embedded assets do.
    public static final String ICON = """
            data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAA\
            C0lEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==iVBORw0KGgoAAAANSUhEUg\
            AAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJg\
            """;

    // A published commit SHA — a public identifier, not a secret.
    public static final String BUILD_COMMIT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b";

    // A Subresource Integrity hash in its natural HTML attribute context — a
    // public content digest that the browser verifies, not a secret.
    public static final String SCRIPT_TAG =
            "<script src=\"/app.js\" integrity=\"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC\"></script>";

    private Assets() {
    }
}
