#!/usr/bin/env bash
# sshd host keys, per-container writable source copy, start service, exec sshd.
set -e
if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi
mkdir -p /srv/challenge/birthdaygram
cp -r /opt/challenge_src/birthdaygram/. /srv/challenge/birthdaygram/
chown -R arena_agent:arena_agent /srv/challenge/birthdaygram
chmod -R u+w /srv/challenge/birthdaygram
/arena/restart.sh || echo "entrypoint: initial service start failed (see /var/log/birthdaygram.log)" >&2
exec /usr/sbin/sshd -D -e
