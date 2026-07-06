// Placeholder / example credentials and config in Java — none is a real secret,
// so a precise scanner fires nothing. These are the strings that a naive secret
// regex trips on: example tokens, obvious placeholders, and values pulled from
// the environment at runtime. Zero findings expected.
package com.example.config;

public final class Config {

    // Obvious placeholders — the kind committed in a template config, never a
    // live credential.
    public static final String API_KEY = "your-api-key-here";
    public static final String DB_PASSWORD = "changeme";
    public static final String SMTP_PASSWORD = "<your-smtp-password>";
    public static final String JDBC_URL = "jdbc:postgresql://USER:PASSWORD@localhost:5432/app";

    // Real secrets are read from the environment, not hardcoded.
    public static String awsKey() {
        return System.getenv("AWS_SECRET_ACCESS_KEY");
    }

    private Config() {
    }
}
