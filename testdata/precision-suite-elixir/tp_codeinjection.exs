# Code injection (CWE-95): an untrusted value is evaluated as Elixir source via
# Code.eval_string, and untrusted bytes are deserialized via
# :erlang.binary_to_term (CWE-502). A correct scanner fires TAINT-005 on each.

defmodule TpCodeInjection do
  # Code.eval_string evaluates its argument as Elixir source.
  def evaluate(conn) do
    code = conn.params["expr"]
    Code.eval_string(code) # nox-expect: TAINT-005
  end

  # :erlang.binary_to_term deserializes untrusted bytes into terms.
  def deserialize(conn) do
    blob = conn.body_params
    :erlang.binary_to_term(blob) # nox-expect: TAINT-005
  end
end
