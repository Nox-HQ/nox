# Command injection: a request-controlled value flows into a shell command with
# no escaping — CWE-78. A correct scanner fires TAINT-002 on each dangerous call.
# Covers the two idioms a Ruby line-recognizer must handle: a paren-less `system`
# and a backtick command literal.
class OpsController
  # Paren-less system call with string interpolation — classic RCE.
  def ping
    host = params[:host]
    system "ping -c 1 #{host}" # nox-expect: TAINT-002
  end

  # Backtick command execution — the command literal has no ordinary call syntax
  # but is a command-injection sink all the same.
  def traceroute
    target = params[:target]
    output = `traceroute #{target}` # nox-expect: TAINT-002
    render plain: output
  end

  # Explicit paren call to exec with a tainted command string.
  def restart
    svc = params[:service]
    exec("systemctl restart #{svc}") # nox-expect: TAINT-002
  end
end
