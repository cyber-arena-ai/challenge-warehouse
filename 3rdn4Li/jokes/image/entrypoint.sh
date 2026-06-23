#!/usr/bin/env bash
# sshd host keys, /etc/team-num (the service reads it at import), per-container
# writable source copy, start the service, then exec sshd as PID 1.
set -e

if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi

# Upstream reads /etc/team-num at import (app.py). One team per vulbox -> 0.
if [ ! -f /etc/team-num ]; then
    echo 0 > /etc/team-num
fi

mkdir -p /srv/challenge/jokes
cp -r /opt/challenge_src/jokes/. /srv/challenge/jokes/
chown -R arena_agent:arena_agent /srv/challenge/jokes
chmod -R u+w /srv/challenge/jokes

/arena/restart.sh || echo "entrypoint: initial service start failed (see /var/log/jokes.log)" >&2

exec /usr/sbin/sshd -D -e
