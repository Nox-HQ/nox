#!/bin/bash
# Clean: input validated with a regex / allowlist before use. A correct scanner
# treats a value gated by `[[ ... =~ ]]` or a case allowlist as constrained, and
# the samples below only ever reach a sink after validation or via a non-sink
# path. Any finding here is a false positive.
set -euo pipefail

# Allowlist validation with a case statement: only known-good verbs proceed.
action="$1"
case "$action" in
  start|stop|restart)
    systemctl "$action" nginx
    ;;
  *)
    echo "unknown action" >&2
    exit 1
    ;;
esac

# Regex validation: reject anything that is not a bare hostname before use.
host="$2"
if [[ "$host" =~ ^[a-zA-Z0-9.-]+$ ]]; then
  ping -c 1 "$host"
fi

# A quoted expansion echoed to a log is not executed as a command.
msg="$3"
echo "request: $msg" >> /var/log/app.log
