# Code injection: a request-controlled string is passed to eval, executing
# attacker-supplied Ruby — CWE-95 (reported under TAINT-005, the eval/deser
# family). A correct scanner fires TAINT-005.
class CalcController
  def evaluate
    expr = params[:expr]
    result = eval(expr) # nox-expect: TAINT-005
    render plain: result
  end
end
