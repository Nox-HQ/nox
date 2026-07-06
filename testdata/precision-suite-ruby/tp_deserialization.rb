# Unsafe deserialization / code execution: request-controlled bytes flow into
# Marshal.load and YAML.load (the unsafe loader), either of which can instantiate
# arbitrary objects and reach RCE — CWE-502. A correct scanner fires TAINT-005.
# The YAML.safe_load form in clean_safe_db.rb must NOT fire.
class SessionController
  def restore
    blob = params[:state]
    obj = Marshal.load(blob) # nox-expect: TAINT-005
    obj
  end

  def import
    doc = params[:doc]
    config = YAML.load(doc) # nox-expect: TAINT-005
    config
  end
end
