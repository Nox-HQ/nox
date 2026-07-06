-- Code injection (CWE-95): an untrusted value is compiled and run as Lua code
-- via loadstring / load. The attacker chooses the program that executes. A
-- correct scanner fires TAINT-005 on each.

-- A CLI argument compiled as a Lua chunk and invoked.
local expr = arg[1]
local fn = loadstring("return " .. expr) -- nox-expect: TAINT-005

-- A value read from stdin loaded as code (load is loadstring's successor).
local src = io.read("*a")
local chunk = load(src) -- nox-expect: TAINT-005
