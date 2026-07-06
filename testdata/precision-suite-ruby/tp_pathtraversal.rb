# Path traversal: a request-controlled filename flows into File.read with no
# containment check, so "../../etc/passwd" escapes the intended directory —
# CWE-22. A correct scanner fires TAINT-004. The File.basename-sanitized form in
# clean_safe_db.rb must NOT fire.
class DownloadsController
  def show
    name = params[:file]
    data = File.read("/srv/downloads/#{name}") # nox-expect: TAINT-004
    send_data data
  end

  def open_config
    path = params[:path]
    contents = File.open(path).read # nox-expect: TAINT-004
    render plain: contents
  end
end
