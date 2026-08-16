#!/usr/bin/env bash
set -euo pipefail

readonly SOURCE=/srv/challenge/gogs
readonly DATA=/srv/gogs-data
readonly CONFIG="$DATA/custom/conf/app.ini"
readonly SENTINEL="$DATA/.bootstrap-complete"

[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A >/dev/null
mkdir -p /run/sshd "$SOURCE" /srv/gogs/bin "$DATA/custom/conf" \
  "$DATA/log" "$DATA/repositories" "$DATA/protected"

if [ ! -f "$SOURCE/go.mod" ]; then
    cp -a /opt/challenge_src/gogs/. "$SOURCE/"
fi
if [ ! -x /srv/gogs/bin/gogs ]; then
    install -o root -g root -m 0755 /opt/gogs-bin /srv/gogs/bin/gogs
fi
if [ ! -f "$CONFIG" ]; then
    secret="$(head -c 48 /dev/urandom | base64 | tr -d '/+=' | cut -c1-48)"
    sed "s/__SECRET_KEY__/${secret}/" /arena/app.ini.template > "$CONFIG"
    chmod 0600 "$CONFIG"
fi

chown -R arena_agent:arena_agent "$SOURCE" "$DATA"
chmod -R u+rwX,go+rX "$SOURCE"
chmod 0700 "$DATA/protected"

/arena/start.sh
if [ ! -f "$SENTINEL" ]; then
    /arena/provision_admin.py http://127.0.0.1:3000
    touch "$SENTINEL"
    chown arena_agent:arena_agent "$SENTINEL"
fi

echo "gogs: ready"
exec /usr/sbin/sshd -D -e
