#!/usr/bin/env bash
set -euo pipefail

source_root=/srv/challenge/grafana
binary=/usr/share/grafana/bin/grafana
candidate=/usr/share/grafana/bin/.grafana.new

rm -f "$candidate"
cd "$source_root"
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
  GOCACHE=/var/cache/grafana-go-build \
  go run build.go -goos linux -goarch amd64 -build-tags=oss build-backend
install -o root -g root -m 0755 \
  "$source_root/bin/linux-amd64/grafana" "$candidate"

/arena/service-control.sh stop
mv -f "$candidate" "$binary"
/arena/service-control.sh start

for _ in $(seq 1 600); do
  curl -fsS http://127.0.0.1:3000/api/health >/dev/null && exit 0
  sleep .1
done
echo "Grafana did not become healthy after reload" >&2
exit 1
