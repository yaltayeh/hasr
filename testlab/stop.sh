#!/bin/sh
# Stop the local TLS test servers started by testlab/start.sh.
set -eu
cd "$(dirname "$0")"
for f in run/*.pid; do
  [ -e "$f" ] || continue
  pid=$(cat "$f")
  kill "$pid" 2>/dev/null && echo "stopped $(basename "$f" .pid) (pid $pid)"
  rm -f "$f"
done
