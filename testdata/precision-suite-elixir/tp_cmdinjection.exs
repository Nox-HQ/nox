# Command injection (CWE-78): an untrusted Phoenix/Plug request value is executed
# as a command line via System.cmd/:os.cmd/Port.open. A correct scanner fires
# TAINT-002 on each sink line.

defmodule TpCmdInjection do
  # System.cmd running a tainted value through `sh -c`.
  def run_shell(conn) do
    cmd = conn.params["cmd"]
    System.cmd("sh", ["-c", cmd]) # nox-expect: TAINT-002
  end

  # :os.cmd/1 runs its argument through the shell.
  def run_os(conn) do
    payload = conn.query_params
    :os.cmd(payload) # nox-expect: TAINT-002
  end

  # Port.open spawning a tainted command string.
  def run_port(conn) do
    prog = conn.body_params
    Port.open(prog) # nox-expect: TAINT-002
  end

  # Multi-stage pipe: the tainted value flows through a TWO-hop pipe chain
  # (`|> String.trim() |> :os.cmd()`) before reaching the sink. Pipe desugaring
  # runs to fixpoint — each rewrite peels the leftmost `|>`, so the chain nests
  # into `:os.cmd(String.trim(conn.params["cmd"]))` and the value lands in the
  # FINAL stage, where the sink is. Caught since the fixpoint rewrite landed.
  def run_piped(conn) do
    conn.params["cmd"] |> String.trim() |> :os.cmd() # nox-expect: TAINT-002
  end
end
