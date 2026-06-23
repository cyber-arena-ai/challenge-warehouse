#!/usr/bin/env bash
set -e
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A
mkdir -p /srv/challenge/treasury/app
cp -r /opt/challenge_src/treasury/app/. /srv/challenge/treasury/app/
mkdir -p /srv/challenge/treasury/app/data
chown -R arena_agent:arena_agent /srv/challenge/treasury
chmod -R u+w /srv/challenge/treasury
/arena/restart.sh || echo "entrypoint: initial start failed (see /var/log/treasury.log)" >&2
exec /usr/sbin/sshd -D -e
