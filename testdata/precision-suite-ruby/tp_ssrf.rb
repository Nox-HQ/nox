# SSRF: a request-controlled URL flows into an outbound HTTP fetch, letting a
# caller reach internal services (169.254.169.254, localhost admin ports) —
# CWE-918. A correct scanner fires TAINT-006.
require "net/http"
require "uri"

class ProxyController
  def fetch
    url = params[:url]
    body = Net::HTTP.get(URI(url)) # nox-expect: TAINT-006
    render plain: body
  end

  def open_remote
    target = params[:target]
    data = URI.open(target).read # nox-expect: TAINT-006
    render plain: data
  end
end
