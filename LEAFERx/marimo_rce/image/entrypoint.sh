#!/usr/bin/env bash

set -euo pipefail

/arena/facility.py initialize >/dev/null

if [ ! -d /srv/challenge/marimo ]; then
    cp -a /opt/marimo-source/marimo /srv/challenge/marimo
fi
if [ ! -f /srv/state/notebook.py ]; then
    install -o marimo -g marimo -m 0644 /opt/notebook.py /srv/state/notebook.py
fi

chown -R arena_agent:arena_agent /srv/challenge/marimo
chmod -R a+rX,u+w /srv/challenge/marimo
chown marimo:marimo /run/marimo /srv/state
chmod 0755 /srv/state
touch /run/marimo/bootstrap-ready

exec /usr/sbin/sshd -D -e
