#!/bin/sh
# Local verified checkout only. There is no official cloud curl-to-shell release.
set -eu
exec /usr/bin/python3 "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/install.py" controller --wizard "$@"
