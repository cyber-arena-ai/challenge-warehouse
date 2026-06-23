#!/usr/bin/env bash
set -e
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A
mkdir -p /srv/challenge/marscasino
cp -r /opt/challenge_src/marscasino/. /srv/challenge/marscasino/
chown -R arena_agent:arena_agent /srv/challenge/marscasino
chmod -R u+w /srv/challenge/marscasino
/arena/restart.sh || echo "entrypoint: initial start failed (see /var/log/marscasino.log)" >&2
exec /usr/sbin/sshd -D -e
