# SQL injection (CWE-89): an untrusted value is interpolated directly into a raw
# Ecto SQL string passed to Repo.query, bypassing parameterization. A correct
# scanner fires TAINT-001. The clean counterpart (parameterized $1 + bind list)
# lives in clean_validated.exs.

defmodule TpSqli do
  def lookup(conn) do
    id = conn.params["id"]
    # The tainted id is interpolated into the SQL string itself (1st positional
    # argument) — classic raw SQLi.
    query = "SELECT * FROM users WHERE id = #{id}"
    Repo.query(query) # nox-expect: TAINT-001
  end
end
