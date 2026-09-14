#!/usr/bin/env bash

set -euo pipefail

if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi
mkdir -p /run/sshd /srv/challenge

if [ ! -d /srv/challenge/pyload ]; then
    cp -a /opt/challenge_src/pyload /srv/challenge/pyload
fi
chown -R arena_agent:arena_agent /srv/challenge/pyload
chmod -R a+rX,u+w /srv/challenge/pyload
chown -R pyload:pyload /srv/pyload

exec /usr/sbin/sshd -D -e
