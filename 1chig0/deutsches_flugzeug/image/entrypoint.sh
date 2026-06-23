#!/usr/bin/env bash
set -e
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A

APP="/srv/challenge/deutsches-flugzeug/app"

# The venv was built in place at ${APP}/venv during the image build (absolute
# paths are baked into pip's shebang + sys.prefix, so it must NOT be relocated).
# Refresh only the app SOURCE from the pristine read-only template, preserving
# the venv and a clean data dir. On a first boot ${APP} already holds the source
# + venv from the build; the rsync-style copy below is idempotent.
if [ -d /opt/challenge_src/deutsches-flugzeug/app ]; then
    cp -a /opt/challenge_src/deutsches-flugzeug/app/dieAnwendung "${APP}/" 2>/dev/null || true
    cp -a /opt/challenge_src/deutsches-flugzeug/app/wsgi.py "${APP}/" 2>/dev/null || true
fi

mkdir -p "${APP}/data"
chown -R arena_agent:arena_agent /srv/challenge/deutsches-flugzeug
chmod -R u+w /srv/challenge/deutsches-flugzeug

# Start the Flask app (gunicorn) as the service user.
/arena/restart.sh || echo "entrypoint: initial start failed (see /var/log/deutsches-flugzeug.log)" >&2

exec /usr/sbin/sshd -D -e
