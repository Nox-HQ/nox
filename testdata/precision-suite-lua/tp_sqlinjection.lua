-- SQL injection (CWE-89): an untrusted value is concatenated into a SQL string
-- passed to a luasql connection:execute (no bind parameters) or an lsqlite3
-- db:exec. A correct scanner fires TAINT-001.

-- luasql: request argument interpolated into the SQL string.
local function lookup(conn)
  local id = ngx.req.get_uri_args().id
  return conn:execute("SELECT * FROM users WHERE id = " .. id) -- nox-expect: TAINT-001
end

-- lsqlite3: a POST argument interpolated into the query.
local function search(db)
  local q = ngx.req.get_post_args().q
  db:exec("SELECT * FROM items WHERE name LIKE '%" .. q .. "%'") -- nox-expect: TAINT-001
end
