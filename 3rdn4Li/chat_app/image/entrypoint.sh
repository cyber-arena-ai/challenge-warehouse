#!/usr/bin/env bash
# Generate sshd host keys, materialize the per-container writable source
# workdir, start the chat-app service, then exec sshd as PID 1.
#
# Unlike nautilus-ico (which defers the first launch to restart.sh), this
# interpreted service is cheap to start, so we bring it up at boot for an
# immediate-ready vulbox. restart.sh handles every subsequent respawn.

set -e

if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi

mkdir -p /srv/challenge/chat-app
cp -r /opt/challenge_src/chat-app/. /srv/challenge/chat-app/
chown -R arena_agent:arena_agent /srv/challenge/chat-app
chmod -R u+w /srv/challenge/chat-app

# Initial launch goes through the same path the MCP restart uses.
/arena/restart.sh || echo "entrypoint: initial service start failed (see /var/log/chatapp.log)" >&2

exec /usr/sbin/sshd -D -e
