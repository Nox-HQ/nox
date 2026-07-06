# Clean: every untrusted value is neutralized before it reaches a sink, so a
# correct scanner fires NOTHING here. A finding on any line is a false positive.

defmodule CleanValidated do
  # Ecto parameterized query: the tainted value is passed as a BIND parameter
  # (2nd positional, the list) rather than interpolated into the SQL string
  # (1st positional). This is the safe, idiomatic form.
  def lookup(conn) do
    id = conn.params["id"]
    Repo.query("SELECT * FROM users WHERE id = $1", [id])
  end

  # String.to_integer coerces the value to an integer, stripping any string
  # payload before it is used as a filename.
  def read_by_id(conn) do
    raw = conn.params["id"]
    id = String.to_integer(raw)
    File.read("/data/#{id}.txt")
  end

  # Path.basename strips directory components, defusing traversal before File.open.
  def read_upload(conn) do
    name = conn.params["file"]
    safe = Path.basename(name)
    File.open(safe)
  end
end
