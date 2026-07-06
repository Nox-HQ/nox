# Clean: a data blob embedded as a Ruby heredoc — a base64 data-URI of the kind
# that populates an icon or a fixture. lexctx classifies the heredoc body as a
# STRING data blob, so the entropy/secret matchers must skip the high-entropy run
# inside it. A finding here is a false positive.
module Assets
  # A base64 data-URI in a squiggly heredoc — pure data, not a secret.
  LOGO = <<~DATA
    data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk
    +M9QDwADhgGAWjR9awAAAABJRU5ErkJgggAKICAgICAgICBkYXRhOmltYWdlL3BuZztiYXNlNjQ
  DATA

  # A word-array literal is data (a list of allowed hosts), not code.
  ALLOWED_HOSTS = %w[api.example.com cdn.example.com static.example.com]

  # A single-quoted git-style SHA — a public digest, not a credential.
  BUILD_SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
end
