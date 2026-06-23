#!/usr/bin/env bash
# sshd host keys, per-container writable source copy (+ data dir), start the
# service, then exec sshd as PID 1.
set -e

if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi

mkdir -p /srv/challenge/fittyfit
cp -r /opt/challenge_src/fittyfit/. /srv/challenge/fittyfit/
# app.py creates data/nft/{generator,damaged} at import; ensure the dir is writable.
mkdir -p /srv/challenge/fittyfit/app/data
chown -R arena_agent:arena_agent /srv/challenge/fittyfit
chmod -R u+w /srv/challenge/fittyfit

/arena/restart.sh || echo "entrypoint: initial service start failed (see /var/log/fittyfit.log)" >&2

exec /usr/sbin/sshd -D -e
