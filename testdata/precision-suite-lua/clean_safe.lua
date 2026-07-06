-- Clean: the SAFE counterparts of the tp_*.lua flows. None of these should fire
-- — each routes the tainted value through the sanitizer / safe form that
-- neutralizes its sink's vuln class, or uses the value only in a non-sink
-- position. A finding on any line here is a false positive.

-- tonumber coerces a value to a number (or nil), stripping every injection
-- metacharacter before it reaches a command sink.
local raw = arg[1]
local n = tonumber(raw)
os.execute("nice -n " .. n)

-- A constant command string is never tainted.
os.execute("systemctl daemon-reload")

-- A constant path into io.open — no untrusted input.
local cfg = io.open("/etc/app/config.ini")

-- ngx.quote_sql_str escapes and quotes a value for safe SQL interpolation.
local function lookup(conn)
  local id = ngx.req.get_uri_args().id
  local safe = ngx.quote_sql_str(id)
  return conn:execute("SELECT * FROM users WHERE id = " .. safe)
end

-- A request value used only in a non-sink position (logged, not executed).
local user = os.getenv("USER")
print("hello " .. user)

-- tonumber applied inline at the sink defuses SSRF-shaped arithmetic: a numeric
-- port is not a URL.
local port = tonumber(ngx.req.get_uri_args().port)
print("listening on " .. port)
