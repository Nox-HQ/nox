# Template injection via `render inline:` — a request-controlled value is
# interpolated into an inline ERB template body, which Rails renders WITHOUT the
# automatic output escaping a normal view gives you. Injected markup / ERB
# executes in the browser (XSS) — CWE-79. A correct scanner fires TAINT-003.
#
# The recognizer gates the `render` sink on a co-located `inline:` / interpolated
# `text:` keyword argument, so ONLY the dangerous unescaped forms fire; the safe
# auto-escaped `render plain:` / `render json:` / `render :template` in
# clean_render.rb must NOT fire.
class TemplatesController
  # `render inline:` with interpolation — classic SSTI/XSS.
  def greeting
    name = params[:name]
    render inline: "<h1>Hello #{name}</h1>" # nox-expect: TAINT-003
  end

  # `render text:` with interpolation — raw unescaped body.
  def echo
    msg = params[:msg]
    render text: "You said: #{msg}" # nox-expect: TAINT-003
  end
end
