# Mixed corpus of real vulnerabilities that stress the boundary of nox's
# intraprocedural Ruby LINE recognizer. Each line is annotated with the rule a
# correct scanner would fire. Some are caught (they score as recall); one is an
# honest false negative the line-recognizer cannot join, recorded here rather than
# quietly omitted — the whole point of an honest measurement corpus. See README
# "Known gaps" for why the miss is missed.
class KnownGapsController
  # CAUGHT — metaprogramming via Object#send. A tainted method name dispatched
  # through `send` is code injection; nox models `send` as a sink whose first
  # argument is the dispatched method name, so this fires TAINT-005.
  def dispatch
    action = params[:action]
    target.send(action, params[:arg]) # nox-expect: TAINT-005
  end

  # FN — cross-method flow through an instance variable. The source lands in
  # @cmd in one action and the sink reads @cmd in another. nox's same-file
  # interprocedural pass tracks LOCAL HELPER CALLS via summaries, not shared
  # object/instance state, so a taint laundered through an @ivar across two
  # methods is not joined. This is the documented boundary of the
  # intraprocedural + local-summary model (identical to the Python/JS limit),
  # not a Ruby-specific defect.
  def capture
    @cmd = params[:cmd]
  end

  def execute_captured
    system @cmd # nox-expect: TAINT-002
  end
end
