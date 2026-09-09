#!/usr/bin/env bash
set -euo pipefail

if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi
mkdir -p /run/sshd

/arena/restart.sh

exec /usr/sbin/sshd -D -e
