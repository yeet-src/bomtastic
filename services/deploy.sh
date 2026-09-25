#!/usr/bin/env bash
# (Re)deploy the bomtastic service on this machine after a build.
#
#   services/deploy.sh node
#   services/deploy.sh hub 10.0.0.2:3450 [more host:port ...]
#
# The daemon reads a unit's script once, when the service is imported,
# so a rebuild is not live until the service is imported again. This
# removes and re-imports; the hub that dials /app reconnects on its own.
set -euo pipefail
cd "$(dirname "$0")/.."
role=${1:-node}; shift || true
args=(--role "$role" --dir "$PWD")
for n in "$@"; do args+=(--node "$n"); done
yeet service remove -f "bom-$role" >/dev/null 2>&1 || true
yeet run -T -q services/conf.js -- "${args[@]}" | yeet service import - -j -q
yeet service start "bom-$role" | tail -1
yeet service tree "bom-$role"
