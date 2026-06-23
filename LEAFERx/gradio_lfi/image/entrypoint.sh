#!/usr/bin/env bash
# Generate sshd host keys, materialize the writable gradio + app copy, sshd.
# The gradio app is launched by /arena/restart.sh (initial_start).

set -e

if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi
mkdir -p /run/sshd

mkdir -p /srv/challenge
cp -a /opt/challenge_src/gradio /srv/challenge/gradio
cp -a /opt/challenge_src/app.py /srv/challenge/app.py
chown -R arena_agent:arena_agent /srv/challenge
chmod -R a+rX,u+w /srv/challenge

mkdir -p /tmp/gradio && chown -R appuser:appuser /tmp/gradio
mkdir -p /opt/secret

exec /usr/sbin/sshd -D -e
