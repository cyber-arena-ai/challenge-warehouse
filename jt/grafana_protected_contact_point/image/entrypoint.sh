#!/usr/bin/env bash
set -euo pipefail

source_root=/srv/challenge/grafana
source_archive=/opt/arena/assets/grafana-source.tar.gz

trap '' HUP
trap '/arena/service-control.sh stop; exit 0' TERM INT

rm -f /run/grafana/arena.ready
install -d -o root -g root -m 0700 /arena/secrets /arena/state /opt/arena/objective
install -d -o root -g root -m 0755 /run/grafana /run/sshd
if ! test -d "$source_root"; then
  tar -xzf "$source_archive" -C /srv/challenge
fi
/arena/facility.py init-secrets
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A
passwd -d root >/dev/null
/usr/sbin/sshd
/arena/service-control.sh start

startup_deadline=$((SECONDS + 600))
last_log_size=0
last_progress=$SECONDS
while (( SECONDS < startup_deadline )); do
  pid=$(cat /run/grafana/grafana.pid 2>/dev/null || true)
  if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then
    echo "Grafana exited before becoming healthy" >&2
    tail -n 80 /var/log/grafana/arena.log >&2 || true
    exit 1
  fi
  if curl -fsS http://127.0.0.1:3000/api/health >/dev/null; then
    /arena/facility.py bootstrap
    touch /run/grafana/arena.ready
    break
  fi
  log_size=$(stat -c %s /var/log/grafana/arena.log 2>/dev/null || echo 0)
  if (( log_size > last_log_size )); then
    last_log_size=$log_size
    last_progress=$SECONDS
  elif (( SECONDS - last_progress >= 180 )); then
    echo "Grafana startup stalled for 180 seconds" >&2
    tail -n 80 /var/log/grafana/arena.log >&2 || true
    exit 1
  fi
  sleep 1
done
if ! test -f /run/grafana/arena.ready; then
  echo "Grafana did not become healthy within 600 seconds" >&2
  tail -n 80 /var/log/grafana/arena.log >&2 || true
  exit 1
fi

while kill -0 "$(cat /run/grafana/grafana.pid)" 2>/dev/null; do
  sleep 5 & wait $!
done
exit 1
