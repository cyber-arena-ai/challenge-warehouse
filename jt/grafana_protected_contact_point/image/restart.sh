#!/usr/bin/env bash
set -euo pipefail

source_root=/srv/challenge/grafana
module_cache=/go/pkg/mod
binary=/usr/share/grafana/bin/grafana
candidate=/usr/share/grafana/bin/.grafana.new
ready=/run/grafana/arena.ready
restarting=/run/grafana/arena.restarting

cleanup() {
  status=$?
  rm -f "$candidate"
  rm -f "$ready"
  /arena/service-control.sh stop || true
  exit "$status"
}
trap cleanup EXIT
touch "$restarting"

test -d "$source_root"
test -d "$module_cache/cache"

rm -f "$candidate"
cd "$source_root"
if ! timeout -k 5s 75s env \
    GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
    GOMODCACHE="$module_cache" \
    GOCACHE=/var/cache/grafana-go-build \
    go run build.go -goos linux -goarch amd64 -build-tags=oss build-backend; then
  echo "Grafana backend build failed or exceeded 75 seconds" >&2
  exit 1
fi
install -o root -g root -m 0755 \
  "$source_root/bin/linux-amd64/grafana" "$candidate"

rm -f "$ready"
/arena/service-control.sh stop
mv -f "$candidate" "$binary"
/arena/service-control.sh start

if ! /arena/wait-grafana.sh http://127.0.0.1:3000/api/health 15; then
  echo "Grafana did not become healthy after reload" >&2
  exit 1
fi
touch "$ready"
rm -f "$restarting"
trap - EXIT
exit 0
