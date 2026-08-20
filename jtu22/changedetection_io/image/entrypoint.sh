#!/usr/bin/env bash
set -euo pipefail

readonly SRC=/srv/challenge/changedetection
readonly PRISTINE=/opt/challenge_src/changedetection

[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A >/dev/null
mkdir -p /run/sshd /srv/changedetection/datastore \
    /var/lib/changedetection/private/reports

if [ ! -e "$SRC/changedetection.py" ]; then
    mkdir -p "$SRC"
    cp -a "$PRISTINE"/. "$SRC"/
fi
chown -R arena_agent:arena_agent "$SRC" /srv/changedetection
chmod -R a+rX,u+w "$SRC"

/arena/start.sh
touch /srv/changedetection/.ready
echo "changedetection: ready"
exec /usr/sbin/sshd -D -e
