#!/usr/bin/env bash
set -euo pipefail

mkdir -p /run/sshd /run/owncloud-arena
ssh-keygen -A >/dev/null 2>&1

if [ ! -f /run/owncloud-arena/credentials.json ]; then
    python3 - <<'PY'
import json
import secrets
from pathlib import Path

path = Path("/run/owncloud-arena/credentials.json")
path.write_text(json.dumps({
    "admin_username": "arena_admin",
    "admin_password": "Oc-Admin-" + secrets.token_urlsafe(32),
    "objective_username": "arena_objectives",
    "objective_password": "Oc-Objective-" + secrets.token_urlsafe(32),
}))
path.chmod(0o600)
PY
fi

eval "$(python3 - <<'PY'
import json
import shlex
from pathlib import Path

data = json.loads(Path('/run/owncloud-arena/credentials.json').read_text())
print('export OWNCLOUD_ADMIN_USERNAME=' + shlex.quote(data['admin_username']))
print('export OWNCLOUD_ADMIN_PASSWORD=' + shlex.quote(data['admin_password']))
PY
)"

export OWNCLOUD_DOMAIN="${HOSTNAME}:8080"
export OWNCLOUD_TRUSTED_DOMAINS="${HOSTNAME},localhost,127.0.0.1"

/usr/bin/entrypoint /usr/bin/owncloud server &
exec /usr/sbin/sshd -D -e
