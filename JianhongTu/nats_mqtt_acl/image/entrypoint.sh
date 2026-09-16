#!/usr/bin/env bash
set -e

[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A
/arena/facility.py initialize
/arena/restart.sh initial
exec /usr/sbin/sshd -D -e
