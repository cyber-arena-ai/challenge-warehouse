#!/usr/bin/env bash
set -e
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A

# Writable copy of the source the defender edits; restart.sh rebuilds from it.
mkdir -p /srv/challenge/btx/app
cp -r /opt/challenge_src/btx/app/. /srv/challenge/btx/app/

# Seed the flat-file state the service reads/writes (cwd = .../app/server/, so
# these live next to it as ../users ../secrets ../blogs ../stats). The template
# carries the guest account 0-1 (empty password) under state/.
APP=/srv/challenge/btx/app
mkdir -p "$APP/users" "$APP/secrets" "$APP/blogs" "$APP/stats"
cp -r "$APP/state/users/."   "$APP/users/"   2>/dev/null || true
cp -r "$APP/state/secrets/." "$APP/secrets/" 2>/dev/null || true

chown -R arena_agent:arena_agent /srv/challenge/btx
chmod -R u+w /srv/challenge/btx

/arena/restart.sh || echo "entrypoint: initial start failed (see /var/log/btx.log)" >&2
exec /usr/sbin/sshd -D -e
