# Path traversal (CWE-22): an untrusted value is used as a file path in
# File.read/File.open/File.stream! with no basename/expand containment. A correct
# scanner fires TAINT-004 on each sink line.

defmodule TpPathTraversal do
  def read_file(conn) do
    path = conn.params["file"]
    File.read(path) # nox-expect: TAINT-004
  end

  def open_file(conn) do
    name = conn.query_params
    File.open(name) # nox-expect: TAINT-004
  end

  def stream_file(conn) do
    p = conn.body_params
    File.stream!(p) # nox-expect: TAINT-004
  end

  # HONEST FALSE NEGATIVE (destructuring pattern match): the tainted value is
  # bound via a map-destructuring match `%{"file" => path} = conn.params`. nox's
  # recognizer binds only a SIMPLE-ident LHS, so `path` is never marked tainted
  # and the File.read below is missed. A correct scanner fires TAINT-004; nox
  # does not — documented in README.md.
  def read_destructured(conn) do
    %{"file" => path} = conn.params
    File.read(path) # nox-expect: TAINT-004
  end
end
