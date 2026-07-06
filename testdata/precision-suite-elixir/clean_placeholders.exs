# Clean: placeholder / example config and prose mentioning dangerous idioms in
# comments. None of this is a live tainted flow, so a finding on any line is a
# false positive.

defmodule CleanPlaceholders do
  # Module attributes with placeholder / example values — not live secrets.
  @api_base "https://api.example.com"
  @default_timeout 5_000
  @greeting "hello world"

  # The real config comes from the environment at runtime and is used only for a
  # constant, non-tainted purpose (logging its presence), never as a sink arg.
  def configured? do
    System.get_env("APP_ENV") != nil
  end

  # Prose mentioning a dangerous idiom is a comment, not executable code:
  #   Code.eval_string(user_input)   <- never do this
  #   System.cmd("sh", ["-c", input]) <- command injection
  #   HTTPoison.get(remote_url)      <- SSRF

  # A fixed, constant command with no tainted input is not injection.
  def version do
    System.cmd("git", ["--version"])
  end
end
