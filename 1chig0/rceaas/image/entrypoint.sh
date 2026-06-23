#!/usr/bin/env bash
set -e
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A
mkdir -p /srv/challenge/rceaas/app
cp -a /opt/challenge_src/rceaas/app/. /srv/challenge/rceaas/app/
# Runtime state the binary creates relative to its cwd (jails/, passwords/).
chown -R arena_agent:arena_agent /srv/challenge/rceaas
chmod -R u+w /srv/challenge/rceaas
/arena/restart.sh || echo "entrypoint: initial start failed (see /var/log/rceaas.log)" >&2
exec /usr/sbin/sshd -D -e
