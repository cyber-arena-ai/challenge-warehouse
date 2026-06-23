#!/usr/bin/env bash
# Generate sshd host keys, materialize the writable app copy, exec sshd.
# The aiohttp server is launched by /arena/restart.sh (initial_start).

set -e

if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi
mkdir -p /run/sshd

mkdir -p /srv/challenge
cp -a /opt/challenge_src/server.py /srv/challenge/server.py
chown -R arena_agent:arena_agent /srv/challenge
chmod -R a+rX,u+w /srv/challenge

mkdir -p /srv/www && chown -R appuser:appuser /srv/www
mkdir -p /opt/secret

exec /usr/sbin/sshd -D -e
