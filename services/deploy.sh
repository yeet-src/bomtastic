#!/usr/bin/env bash
# (Re)deploy the bomtastic service on this machine after a build.
#
#   services/deploy.sh                                  # a node
#   services/deploy.sh 10.0.0.2:3450 [more host:port ...]   # a hub: a node plus a proxy route per peer
#
# `apply` rolls a rebuilt dist/ out in place; the hub that dials /app
# reconnects on its own. Peers are routes mounted on the gateway, so a
# hub is the same service with more routes.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f dist/server.js ]] || { echo "build first: npm run build" >&2; exit 1; }
yeet service apply -y -f service.toml | tail -1
for node in "$@"; do
  host=${node%%:*}; host=${host//./-}
  yeet service mount bomtastic/gateway -L "/nodes/$host" -U "ws://$node/" -d "bomtastic on $node" 2>/dev/null || true
done
yeet service tree bomtastic
