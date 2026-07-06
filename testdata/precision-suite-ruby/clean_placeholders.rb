# Clean: placeholder / example credentials and config, the kind that populate a
# Rails secrets template or a .env.example. These are NOT real secrets and must
# not fire the secrets analyzer.
module ExampleConfig
  # Obvious placeholders — the value is the literal word, not a credential.
  API_KEY = "your-api-key-here"
  SECRET_TOKEN = "changeme"
  DATABASE_PASSWORD = "example-password"

  # Env-driven config with a documented default that is plainly a placeholder.
  def self.smtp_password
    ENV.fetch("SMTP_PASSWORD", "REPLACE_WITH_YOUR_PASSWORD")
  end

  # A redacted value in an example — the x's make it unmistakably fake.
  STRIPE_KEY = "sk_test_xxxxxxxxxxxxxxxxxxxxxxxx"
end
