#!/bin/sh
# Local reviewed-checkout entry. Public download commands are in the product README.
set -eu
exec /usr/bin/python3 "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/install.py" controller --wizard "$@"
