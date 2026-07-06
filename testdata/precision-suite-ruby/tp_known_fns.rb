# Honest false negatives: real vulnerabilities a CORRECT scanner should flag but
# nox's intraprocedural Ruby LINE recognizer does NOT catch yet. Each is
# annotated with the rule a correct scanner would fire, so it scores as a
# recall gap (FN) rather than being quietly omitted — the whole point of an
# honest measurement corpus. See README "Known gaps" for why each is missed.
class KnownGapsController
  # FN #1 — `render inline:` template injection. A tainted value in an inline
  # ERB template is real XSS/SSTI, but the recognizer keys sinks by call NAME and
  # cannot distinguish `render inline:` (dangerous) from `render plain:`/`json:`
  # (auto-escaped, safe). Firing on bare `render` over-fired the clean auto-
  # escaped renders, so the `render` sink was intentionally dropped. Result: this
  # genuine flow is missed.
  def template
    name = params[:name]
    render inline: "<h1>Hello #{name}</h1>" # nox-expect: TAINT-003
  end

  # FN #2 — cross-method flow through an instance variable. The source lands in
  # @cmd in one action and the sink reads @cmd in another. nox's same-file
  # interprocedural pass tracks LOCAL HELPER CALLS via summaries, not shared
  # object/instance state, so a taint laundered through an @ivar across two
  # methods is not joined.
  def capture
    @cmd = params[:cmd]
  end

  def execute_captured
    system @cmd # nox-expect: TAINT-002
  end

  # FN #3 — metaprogramming via Object#send. A tainted method name dispatched
  # through `send` is code injection, but the argument is a method-name string,
  # not a value flowing into a recognized sink shape; the line recognizer does
  # not model dynamic dispatch.
  def dispatch
    action = params[:action]
    target.send(action, params[:arg]) # nox-expect: TAINT-005
  end
end
