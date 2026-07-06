-- Clean: a data-blob long string and a generated banner. The long-string body is
-- opaque DATA (a base64 payload), not executable Lua; its long alphanumeric runs
-- must not trip secret/entropy rules, and no taint sink fires. A finding on any
-- line here is a false positive.

-- A base64 asset embedded as a Lua long string. lexctx classifies the body as a
-- STRING data blob, so a secret-shaped run inside it is noise, not a credential.
local icon = [[data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg0KGdGVuZXJhdGVkQmxvYlN0cmluZ0FLSUFJT1NGT0ROTjdFWEFNUExFREFUQUJMT0JMT05HTElORTEyMzQ1Njc4OTA=]]

-- A leveled long string used as a config template — the `]]` inside does not
-- close the outer `]==]` bracket, so the whole body stays string data.
local template = [==[
[server]
bind = all-interfaces
tags = [[prod]] [[edge]]
secret_key = REPLACE_WITH_A_REAL_KEY_AT_DEPLOY_TIME
]==]

return icon, template
