#!/usr/bin/env bash
set -euo pipefail

source_root=/srv/challenge/grafana
source_archive=/opt/arena/assets/grafana-source.tar.gz
module_cache=/go/pkg/mod
module_archive=/opt/arena/assets/grafana-go-mod.tar.gz

trap '' HUP
trap '/arena/service-control.sh stop; exit 0' TERM INT

rm -f /run/grafana/arena.ready /run/grafana/arena.restarting
install -d -o root -g root -m 0700 /arena/secrets /arena/state /opt/arena/objective
install -d -o root -g root -m 0755 /run/grafana /run/sshd
if ! test -d "$source_root"; then
  tar -xzf "$source_archive" -C /srv/challenge
fi
if ! test -d "$module_cache/cache"; then
  tar -xzf "$module_archive" -C "$module_cache"
fi
/arena/facility.py init-secrets
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A
passwd -d root >/dev/null
/usr/sbin/sshd
/arena/service-control.sh start

for _ in $(seq 1 1200); do
  if curl -fsS http://127.0.0.1:3000/api/health >/dev/null; then
    /arena/facility.py bootstrap
    touch /run/grafana/arena.ready
    break
  fi
  sleep .1
done
test -f /run/grafana/arena.ready

while true; do
  if test -f /run/grafana/arena.ready; then
    pid=$(cat /run/grafana/grafana.pid 2>/dev/null || true)
    if ! test -n "$pid" || ! kill -0 "$pid" 2>/dev/null; then
      test -f /run/grafana/arena.restarting || exit 1
    fi
  fi
  sleep 5 & wait $!
done
