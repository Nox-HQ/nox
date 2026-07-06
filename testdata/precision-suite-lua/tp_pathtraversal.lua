-- Path traversal (CWE-22): an untrusted value is used as the path argument of
-- io.open, so `../` sequences escape the intended directory. A correct scanner
-- fires TAINT-004.

-- A CLI argument opened directly as a file path.
local name = arg[1]
local f = io.open("/var/app/data/" .. name) -- nox-expect: TAINT-004

-- An OpenResty request argument opened as a path.
local rel = ngx.req.get_uri_args().file
local fh = io.open(rel) -- nox-expect: TAINT-004
