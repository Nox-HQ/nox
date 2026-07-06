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

  # HONEST FALSE NEGATIVE (multi-stage pipe): the tainted value flows through a
  # TWO-hop pipe chain (`|> String.trim() |> :os.cmd()`) before reaching the
  # sink. nox's per-line pipe desugaring only binds the value into the FIRST
  # stage, so a value sunk two-plus hops downstream is missed. A correct scanner
  # fires TAINT-002; nox does not — documented in README.md.
  def run_piped(conn) do
    conn.params["cmd"] |> String.trim() |> :os.cmd() # nox-expect: TAINT-002
  end
end
