# True positives for the Elixir `alias …, as:` idiom.
#
# Elixir sinks are named BARE in the catalog (`System.cmd`, `Repo.query`),
# which is what unaliased code writes. An `as:` rename made the same call
# invisible, so this sample resolves to the last segment rather than the whole
# path -- the form the catalog actually carries.
#
# The suite had no Elixir sample, so nothing measured this either way.
defmodule Precision.AliasIdioms do
  alias System, as: Sys

  def aliased_cmd(conn) do
    cmd = conn.params
    Sys.cmd("sh", ["-c", cmd])  # nox-expect: TAINT-002
  end
end
