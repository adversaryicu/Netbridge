#!/usr/bin/env sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$#" -eq 0 ]; then
  set -- install
fi
exec python3 "$SCRIPT_DIR/scripts/netbridge-manage.py" "$@"
