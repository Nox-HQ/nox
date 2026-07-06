# SSRF (CWE-918): an untrusted value is used as the request URL of an outbound
# HTTP client (HTTPoison / :httpc / Req). A correct scanner fires TAINT-006 on
# each sink line.

defmodule TpSsrf do
  def fetch_httpoison(conn) do
    url = conn.params["url"]
    HTTPoison.get(url) # nox-expect: TAINT-006
  end

  def fetch_httpc(conn) do
    target = conn.query_params
    :httpc.request(target) # nox-expect: TAINT-006
  end

  def fetch_req(conn) do
    endpoint = conn.body_params
    Req.get(endpoint) # nox-expect: TAINT-006
  end
end
