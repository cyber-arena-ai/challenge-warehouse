#!/usr/bin/env bash
# Generate sshd host keys, materialize the writable pyload source copy, sshd.
# pyLoad is launched by /arena/restart.sh (initial_start).

set -e

if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi
mkdir -p /run/sshd

mkdir -p /srv/challenge
cp -a /opt/challenge_src/pyload /srv/challenge/pyload
chown -R arena_agent:arena_agent /srv/challenge
chmod -R a+rX,u+w /srv/challenge

chown -R pyload:pyload /srv/pyload
mkdir -p /opt/secret

exec /usr/sbin/sshd -D -e
