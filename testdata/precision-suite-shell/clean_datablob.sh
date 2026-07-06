#!/bin/bash
# Clean: a data-blob heredoc and a generated banner. The heredoc body is opaque
# data (a base64 payload and a config template), not executable shell; its long
# alphanumeric runs must not trip secret/entropy rules, and no taint sink fires.
# A finding on any line here is a false positive.
set -euo pipefail

# A base64 asset embedded as a here-document. The body is DATA (string), so a
# secret-shaped run inside it is noise, not a live credential.
cat > /tmp/asset.b64 <<'EOF'
iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk
YPhfDwAChwGA60e6kgAAAABJRU5ErkJggg0KGdGVuZXJhdGVkQmxvYlN0cmluZw
QUtJQUlPU0ZPRE5ON0VYQU1QTEVEQVRBQkxPQkxPTkdMSU5FMTIzNDU2Nzg5MA0K
EOF

# A quoted heredoc used as a config template — no interpolation, no sink.
cat > /etc/app/config.ini <<'CONFIG'
[server]
bind = all-interfaces
port = 8080
secret_key = REPLACE_WITH_A_REAL_KEY_AT_DEPLOY_TIME
CONFIG
