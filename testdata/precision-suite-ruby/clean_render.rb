# Clean: the SAFE `render` forms. Rails auto-escapes `render plain:`, serializes
# `render json:`, and looks up a template by name for `render :symbol` /
# `render template:` — none build an unescaped ERB body from the tainted value,
# so none is XSS. A finding on any line here is a false positive. These are the
# counterparts the `inline:`/`text:` gate must distinguish from tp_render_inline.rb.
class SafeRenderController
  # Plain-text render: the body is escaped/served verbatim as text/plain, not HTML.
  def as_text
    output = params[:output]
    render plain: output
  end

  # JSON render: the value is serialized, not interpolated into a template.
  def as_json
    data = params[:data]
    render json: data
  end

  # Template lookup by symbol: no tainted template body at all.
  def show
    @row = params[:id]
    render :show
  end

  # Named template option: renders a fixed on-disk view, not an inline body.
  def named
    @row = params[:id]
    render template: "records/show"
  end
end
