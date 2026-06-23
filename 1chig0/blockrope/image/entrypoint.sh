#!/usr/bin/env bash
set -e
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A
mkdir -p /srv/challenge/blockrope/app
cp -r /opt/challenge_src/blockrope/app/. /srv/challenge/blockrope/app/
# Runtime state the service writes to (relative to its cwd).
mkdir -p /srv/challenge/blockrope/app/accounts /srv/challenge/blockrope/app/logs
chown -R arena_agent:arena_agent /srv/challenge/blockrope
chmod -R u+w /srv/challenge/blockrope
/arena/restart.sh || echo "entrypoint: initial start failed (see /var/log/blockrope.log)" >&2
exec /usr/sbin/sshd -D -e
