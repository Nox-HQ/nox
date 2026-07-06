-- Command injection (CWE-78): an untrusted value is passed to os.execute /
-- io.popen, which run their argument through the system shell. A value
-- concatenated (Lua uses `..`) into the command word is command injection. A
-- correct scanner fires TAINT-002 on each.

-- A CLI argument executed via os.execute.
local target = arg[1]
os.execute("systemctl restart " .. target) -- nox-expect: TAINT-002

-- An environment variable piped through io.popen.
local host = os.getenv("PING_HOST")
local handle = io.popen("ping -c 1 " .. host) -- nox-expect: TAINT-002

-- A value read from stdin executed as a shell command.
local line = io.read("*l")
os.execute(line) -- nox-expect: TAINT-002
