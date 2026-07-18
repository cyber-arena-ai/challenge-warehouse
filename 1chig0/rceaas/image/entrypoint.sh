#!/usr/bin/env bash
set -e
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A
mkdir -p /srv/challenge/rceaas/app
cp -a /opt/challenge_src/rceaas/app/. /srv/challenge/rceaas/app/
# Pre-create the runtime state dirs (jails/, passwords/) the binary uses relative
# to its cwd, owned by the service user. Otherwise whoever FIRST touches them
# owns them: the round-0 flag plant runs as root (docker exec: `mkdir -p
# jails/vault`), so if it wins the race against the service creating jails/, that
# dir becomes root-owned and every subsequent non-root login (health checker,
# attackers) panics on `create_dir_all(jails/<user>)`. Creating them here, before
# the service starts, makes ownership deterministic regardless of plant timing.
mkdir -p /srv/challenge/rceaas/app/jails /srv/challenge/rceaas/app/passwords
# Runtime state the binary creates relative to its cwd (jails/, passwords/).
chown -R arena_agent:arena_agent /srv/challenge/rceaas
chmod -R u+w /srv/challenge/rceaas
/arena/restart.sh || echo "entrypoint: initial start failed (see /var/log/rceaas.log)" >&2
exec /usr/sbin/sshd -D -e
