# XSS: request-controlled text is marked html_safe (or emitted via raw),
# defeating Rails' automatic output escaping so injected markup executes in the
# browser — CWE-79. A correct scanner fires TAINT-003. The CGI.escapeHTML form in
# clean_safe_db.rb must NOT fire.
class CommentsController
  def preview
    body = params[:body]
    @html = body.html_safe # nox-expect: TAINT-003
  end
end
