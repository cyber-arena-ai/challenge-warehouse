#!/usr/bin/env bash
set -e
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A
mkdir -p /srv/challenge/certified-transparency/app
cp -a /opt/challenge_src/certified-transparency/app/. /srv/challenge/certified-transparency/app/
# Runtime state the binaries create relative to their cwd (data/, data-client/).
chown -R arena_agent:arena_agent /srv/challenge/certified-transparency
chmod -R u+w /srv/challenge/certified-transparency
/arena/restart.sh || echo "entrypoint: initial start failed (see /var/log/ct-*.log)" >&2
exec /usr/sbin/sshd -D -e
