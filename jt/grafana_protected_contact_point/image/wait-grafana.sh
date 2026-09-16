#!/usr/bin/env bash
set -euo pipefail

url=${1:?Grafana health URL required}
attempts=${2:?attempt count required}

for _ in $(seq 1 "$attempts"); do
  if curl -fsS --max-time 1 "$url" >/dev/null; then
    exit 0
  fi
  sleep .1
done
exit 1
