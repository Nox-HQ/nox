-- SSRF (CWE-918): an untrusted URL is fetched by an HTTP client, letting an
-- attacker make the server issue requests to internal or arbitrary hosts. A
-- correct scanner fires TAINT-006.

-- LuaSocket: a request argument used as the fetch URL.
local function fetch()
  local url = ngx.req.get_uri_args().url
  local body = http.request(url) -- nox-expect: TAINT-006
  return body
end

-- lua-resty-http: a request argument used as the target URI.
local function proxy(httpc)
  local target = ngx.req.get_uri_args().target
  local res = httpc:request_uri(target) -- nox-expect: TAINT-006
  return res
end
