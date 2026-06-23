#!/usr/bin/env bash
# Generate sshd host keys, materialize the writable marimo source copy + the
# notebook, exec sshd. marimo is launched by /arena/restart.sh (initial_start).

set -e

if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi
mkdir -p /run/sshd

mkdir -p /srv/challenge/marimo
cp -a /opt/challenge_src/marimo/. /srv/challenge/marimo/
chown -R arena_agent:arena_agent /srv/challenge
chmod -R a+rX,u+w /srv/challenge

mkdir -p /srv/marimo
cp -a /opt/challenge_src/nb.py /srv/marimo/nb.py
chown -R marimo:marimo /srv/marimo

mkdir -p /opt/secret

exec /usr/sbin/sshd -D -e
