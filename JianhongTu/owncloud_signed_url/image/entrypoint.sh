#!/usr/bin/env bash
set -euo pipefail

SOURCE=/srv/challenge/owncloud
RUNTIME_ROOT=/var/lib/owncloud-arena/generations
CURRENT=/var/lib/owncloud-arena/current
LAST_GOOD=/var/lib/owncloud-arena/last-good
READY=/run/owncloud-arena/ready

mkdir -p /run/sshd /run/owncloud-arena
install -d -o root -g root -m 0755 /var/lib/owncloud-arena "${RUNTIME_ROOT}"
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
export OWNCLOUD_TRUSTED_DOMAINS="${HOSTNAME},${HOSTNAME%_prod}_ingress,localhost,127.0.0.1"

initial="${RUNTIME_ROOT}/initial"
if [ ! -d "${initial}" ]; then
    pending="${RUNTIME_ROOT}/.initial.pending"
    rm -rf "${pending}"
    cp -a "${SOURCE}" "${pending}"
    rm -rf "${pending}/config" "${pending}/custom"
    ln -s /mnt/data/config "${pending}/config"
    ln -s /mnt/data/apps "${pending}/custom"
    chown -R root:www-data "${pending}"
    chmod -R u+rwX,go=rX "${pending}"
    mv "${pending}" "${initial}"
fi
chown www-data:root "${initial}/.htaccess"
chmod 0644 "${initial}/.htaccess"

ln -sfn "${initial}" "${CURRENT}"
rm -rf /var/www/owncloud
ln -s "${CURRENT}" /var/www/owncloud
cd /var/www/owncloud

set +u
for script in $(find /etc/entrypoint.d -iname "*.sh" | sort); do
    . "${script}"
done
set -u
/usr/bin/owncloud true
for script in $(find "${OWNCLOUD_PRE_SERVER_PATH}" -iname "*.sh" | sort); do
    . "${script}"
done
apache2ctl start

for _ in $(seq 1 180); do
    if curl -fsS --max-time 3 http://127.0.0.1:8080/status.php \
        | grep -q '"installed":true'; then
        ln -sfn "${initial}" "${LAST_GOOD}"
        touch "${READY}"
        exec /usr/sbin/sshd -D -e
    fi
    sleep 1
done

pkill -TERM -x apache2 >/dev/null 2>&1 || true
echo "ownCloud did not become ready" >&2
exit 1
