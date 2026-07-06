# Clean: a large base64/data-URI blob embedded in a heredoc string. lexctx marks
# the heredoc body as a data blob so a pattern that fires inside it is suppressed;
# no tainted value flows to any sink. A finding here is a false positive.

defmodule CleanDataBlob do
  # An embedded SVG icon as a data URI — data, not code, not a secret.
  @icon """
  data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmci
  IHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZD0iTTEyIDJMMiA3djEwbDEwIDUgMTAtNVY3eiIvPjwv
  c3ZnPkFLSUExMjM0NTY3ODkwQUJDREVGMTIzNDU2Nzg5MEFC
  """

  # A long charlist heredoc of encoded binary data (also a blob). Kept on one
  # long line so it comfortably clears the data-blob length threshold and is
  # suppressed rather than mistaken for a token.
  @payload '''
  QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY3ODk=
  '''

  def icon, do: @icon
  def payload, do: @payload
end
