#!/bin/sh
# Never run on the financial test server. Packages require explicit wizard approval; never changes host networks.
set -eu
exec /usr/bin/python3 "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/install.py" node --wizard "$@"
