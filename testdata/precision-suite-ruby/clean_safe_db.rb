# Clean: the SAFE counterparts of every tp_*.rb flow. None of these should fire —
# each routes the tainted value through the sanitizer / parameterized form that
# neutralizes its sink's vuln class. A finding on any line here is a false
# positive.
class SafeController
  # Parameterized ActiveRecord: the tainted value is a bind parameter (2nd arg),
  # not interpolated into the SQL string — safe against SQL injection.
  def by_user
    id = params[:user_id]
    User.where("id = ?", id)
  end

  # Integer coercion strips every injection metacharacter before the value is
  # used in a shell command.
  def ping
    raw = params[:count]
    count = Integer(raw)
    system "ping -c #{count} example.com"
  end

  # Shellwords.escape neutralizes command injection.
  def lookup
    host = params[:host]
    safe = Shellwords.escape(host)
    system "host #{safe}"
  end

  # File.basename strips directory components, defusing path traversal.
  def download
    name = params[:file]
    base = File.basename(name)
    File.read("/srv/downloads/#{base}")
  end

  # YAML.safe_load refuses to instantiate arbitrary objects — safe deserialization.
  def import
    doc = params[:doc]
    YAML.safe_load(doc)
  end

  # CGI.escapeHTML neutralizes XSS before the value is marked html_safe.
  def preview
    body = params[:body]
    escaped = CGI.escapeHTML(body)
    @html = escaped.html_safe
  end

  # No source: a constant command is never tainted.
  def status
    system "systemctl status nginx"
  end
end
