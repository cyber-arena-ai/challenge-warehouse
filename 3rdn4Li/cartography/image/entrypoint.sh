#!/usr/bin/env bash
set -e
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A
mkdir -p /srv/challenge/cartography/app
cp -r /opt/challenge_src/cartography/app/. /srv/challenge/cartography/app/
mkdir -p /srv/challenge/cartography/app/data
chown -R arena_agent:arena_agent /srv/challenge/cartography
chmod -R u+w /srv/challenge/cartography
/arena/restart.sh || echo "entrypoint: initial start failed (see /var/log/cartography.log)" >&2
exec /usr/sbin/sshd -D -e
